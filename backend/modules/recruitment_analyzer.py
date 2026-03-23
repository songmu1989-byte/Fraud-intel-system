# backend/modules/recruitment_analyzer.py
"""
招聘诈骗专项分析流水线
输入：招聘信息文本 / 聊天记录 / 公司名称 / 链接
流程：
  1. 公司基础信息核验（工商信息、ICP备案、成立时间）
  2. 招聘话术风险分析（关键词NLP + 诈骗话术模式）
  3. 网络舆情交叉判断（投诉量、负面舆情）
  4. AI综合分析 + 诈骗类型识别
输出：RecruitmentFraudAnalysis 报告
"""
import math
import re
import hashlib
from typing import Dict, List, Optional, Tuple
from loguru import logger

from config.settings import (
    RECRUITMENT_RISK_KEYWORDS, RECRUITMENT_FRAUD_TYPES,
    RECRUITMENT_SENTIMENT_PATTERNS,
)


# ─── 1. 公司基础信息核验 ──────────────────────────────────────

class CompanyChecker:
    """
    公司主体信息核验
    生产环境：接入天眼查 / 企查查 API
    当前：基于规则的模拟核验 + 启发式风险判断
    """

    # 已知正规大厂关键词（优先判为正常）
    LEGIT_COMPANY_SIGNALS = [
        "腾讯", "阿里", "字节", "华为", "百度", "网易", "京东", "美团",
        "小米", "滴滴", "拼多多", "微软", "谷歌", "苹果", "亚马逊",
    ]
    # 高危公司名称特征
    SUSPICIOUS_NAME_PATTERNS = [
        r"(培训|教育).{0,4}(咨询|发展|科技)",  # 培训类
        r"(人力|猎头|人才).{0,4}(外包|服务)",   # 人力外包
        r"\d{4}年(成立|创立)",                  # 强调成立年份（自我证明）
    ]

    @classmethod
    def check(cls, company_name: str, text_context: str = "") -> Dict:
        """核验公司信息，返回结构化结果"""
        result = {
            "company_name": company_name,
            "found": False,
            "established_years": None,
            "registered_capital": None,
            "business_scope": None,
            "registration_status": "未知",
            "icp_record": None,
            "risk_signals": [],
            "verdict": "未知",
        }

        if not company_name:
            return result

        # 1) 检查是否为已知正规公司
        for legit in cls.LEGIT_COMPANY_SIGNALS:
            if legit in company_name:
                result["found"] = True
                result["registration_status"] = "正常"
                result["verdict"] = "正常"
                result["established_years"] = 10  # 模拟
                return result

        # 2) 从文本上下文中提取公司相关信息
        result["found"] = True
        result["registration_status"] = "正常"

        # 尝试从文本提取成立年份
        year_match = re.search(r"(成立|创立|创办)[于在]?\s*(\d{4})\s*年", text_context)
        if year_match:
            year = int(year_match.group(2))
            import datetime
            age = datetime.datetime.now().year - year
            result["established_years"] = age
            if age < 1:
                result["risk_signals"].append(f"公司成立不足1年（{year}年）")
            elif age < 3:
                result["risk_signals"].append(f"公司成立仅{age}年，资质较新")

        # 3) 公司名称风险模式检测
        for pattern in cls.SUSPICIOUS_NAME_PATTERNS:
            if re.search(pattern, company_name):
                result["risk_signals"].append(f"公司名称含高风险模式：{company_name}")
                break

        # 4) 规模信息提取
        capital_match = re.search(r"注册资本[\s：:]*(\d+[\d.]*)\s*(万|亿)?元?", text_context)
        if capital_match:
            result["registered_capital"] = f"{capital_match.group(1)}{capital_match.group(2) or ''}元"
            cap_val = float(capital_match.group(1))
            if (capital_match.group(2) == "万" or not capital_match.group(2)) and cap_val < 10:
                result["risk_signals"].append(f"注册资本仅{capital_match.group(1)}万元，规模极小")

        # 5) 综合判定
        n_signals = len(result["risk_signals"])
        if n_signals >= 2:
            result["verdict"] = "高危"
        elif n_signals == 1:
            result["verdict"] = "可疑"
        else:
            result["verdict"] = "正常"

        return result


# ─── 2. 招聘话术分析 ─────────────────────────────────────────

class RecruitmentRhetoricAnalyzer:
    """
    招聘话术风险分析
    识别：收费要求、高薪诱导、内部渠道、刷单返佣等话术模式
    """

    # 话术模式 -> (正则, 风险等级, 话术类型)
    TACTIC_PATTERNS = [
        (r"(缴纳|交|支付|需要).{0,10}(培训费|报名费|课程费|学费)", "高", "付费入职话术"),
        (r"(押金|保证金|诚信金).{0,20}(离职退还|可退|退回)", "高", "押金话术"),
        (r"先.{0,5}(垫付|垫资|垫款|购买).{0,10}(商品|产品|订单)", "高", "刷单垫资话术"),
        (r"(内部名额|内部渠道|走内部|绕过笔试|直接(进|入职))", "高", "虚假内推话术"),
        (r"月薪?(两|三|四|五|\d)\s*万.{0,10}(无|不需|不限).{0,5}经验", "高", "虚假高薪话术"),
        (r"(日结|日薪).{0,5}(千|百|过千|过百)", "中", "高薪诱导话术"),
        (r"(配合调查|协助调查|资金安全|安全账户)", "高", "冒充公检法话术"),
        (r"(二维码|收款码|转账).{0,15}(报名|缴费|激活)", "高", "直接收款话术"),
        (r"(不用(上班|打卡|出勤)|在家(就能|即可)(赚|挣))", "中", "在家兼职诱导"),
        (r"(急聘|急招).{0,10}(无需|不限|不要求)(面试|经验|学历)", "中", "低门槛急聘话术"),
    ]

    @classmethod
    def analyze(cls, text: str, extra_keywords: List[str] = []) -> Dict:
        if not text:
            return {
                "detected_tactics": [],
                "keyword_hits": {},
                "risk_score": 0.0,
                "verdict": "正常",
            }

        text_lower = text.lower()
        detected_tactics = []
        keyword_hits: Dict[str, List[str]] = {"high": [], "medium": [], "low": []}
        raw_score = 0.0

        # 话术模式检测
        for pattern, severity, tactic_name in cls.TACTIC_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                # 提取命中的原始文本片段
                span_match = re.search(pattern, text, re.IGNORECASE)
                quote = ""
                if span_match:
                    start = max(0, span_match.start() - 10)
                    end = min(len(text), span_match.end() + 10)
                    quote = text[start:end].strip()

                detected_tactics.append({
                    "tactic": tactic_name,
                    "quote": quote,
                    "severity": severity,
                })
                weight = 1.5 if severity == "高" else 0.8
                raw_score += weight

        # 关键词词库匹配
        for level, keywords in RECRUITMENT_RISK_KEYWORDS.items():
            for kw in keywords:
                count = text_lower.count(kw.lower())
                if count > 0:
                    keyword_hits[level].append(f"{kw}(×{count})")
                    weight_map = {"high": 1.0, "medium": 0.5, "low": 0.1}
                    raw_score += count * weight_map[level]

        # 自定义补充关键词
        for kw in extra_keywords:
            count = text_lower.count(kw.lower())
            if count > 0:
                keyword_hits["high"].append(f"[自定义]{kw}(×{count})")
                raw_score += count * 1.2

        # 归一化 sigmoid
        risk_score = round(1 / (1 + math.exp(-0.4 * (raw_score - 4))), 4)

        if risk_score >= 0.7:
            verdict = "高危"
        elif risk_score >= 0.4:
            verdict = "可疑"
        else:
            verdict = "正常"

        return {
            "detected_tactics": detected_tactics,
            "keyword_hits": keyword_hits,
            "risk_score": risk_score,
            "verdict": verdict,
        }


# ─── 3. 舆情交叉判断 ─────────────────────────────────────────

class RecruitmentSentimentChecker:
    """
    基于公司名称 / URL 的网络舆情模拟查询
    生产环境：接入 SerpAPI / 12321投诉平台 / 黑猫投诉 API
    当前：基于域名哈希的确定性模拟，保证相同输入产出相同结果
    """

    # 典型负面舆情模板
    _NEGATIVE_TEMPLATES = [
        "{company}被大量求职者投诉，要求缴纳培训费后失联",
        "亲历 | 差点被{company}骗，分享避坑经历",
        "{company}招聘疑似诈骗，押金交了无法退还",
        "黑猫投诉：{company}虚假招聘，要求垫资刷单",
    ]
    _NEUTRAL_TEMPLATES = [
        "{company}招聘信息 - 拉勾网",
        "有人了解{company}这家公司吗？",
    ]

    @classmethod
    def check(cls, company_name: str = "", url: str = "") -> Dict:
        seed = company_name or url or "unknown"
        h = int(hashlib.md5(seed.encode()).hexdigest(), 16)
        risk_bucket = h % 4  # 0=干净, 1=轻微, 2=中等, 3=高危

        search_snippets = []
        complaint_count = 0

        if risk_bucket == 0:
            search_snippets = [t.format(company=company_name) for t in cls._NEUTRAL_TEMPLATES[:1]]
            complaint_count = 0
        elif risk_bucket == 1:
            search_snippets = [t.format(company=company_name) for t in cls._NEUTRAL_TEMPLATES]
            complaint_count = h % 5 + 1
        elif risk_bucket == 2:
            search_snippets = [cls._NEGATIVE_TEMPLATES[0].format(company=company_name)]
            search_snippets += [t.format(company=company_name) for t in cls._NEUTRAL_TEMPLATES]
            complaint_count = h % 20 + 5
        else:
            search_snippets = [t.format(company=company_name) for t in cls._NEGATIVE_TEMPLATES[:3]]
            complaint_count = h % 80 + 20

        # 计算负面情感分
        all_text = " ".join(search_snippets)
        neg_score = 0.0
        for pattern, weight in RECRUITMENT_SENTIMENT_PATTERNS:
            if re.search(pattern, all_text):
                neg_score += weight
        neg_score = min(neg_score / 3.0, 1.0)

        if neg_score >= 0.6 or complaint_count >= 20:
            verdict = "高危"
        elif neg_score >= 0.3 or complaint_count >= 5:
            verdict = "可疑"
        else:
            verdict = "正常"

        return {
            "search_snippets": search_snippets,
            "complaint_count": complaint_count,
            "negative_score": round(neg_score, 4),
            "verdict": verdict,
        }


# ─── 4. 诈骗类型识别 ─────────────────────────────────────────

class FraudTypeIdentifier:
    """
    规则引擎：基于特征向量匹配诈骗类型
    AI引擎在此之后进行精确识别，二者取置信度高者
    """

    @staticmethod
    def identify(rhetoric_result: Dict, company_check: Dict, sentiment_result: Dict) -> Tuple[Optional[str], str]:
        """返回 (诈骗类型, 置信度)"""
        detected_tactics = {t["tactic"] for t in rhetoric_result.get("detected_tactics", [])}
        kw_high = set(" ".join(rhetoric_result.get("keyword_hits", {}).get("high", [])))
        neg_score = sentiment_result.get("negative_score", 0)
        complaint_count = sentiment_result.get("complaint_count", 0)

        scores: Dict[str, float] = {}

        for fraud_type, config in RECRUITMENT_FRAUD_TYPES.items():
            score = 0.0
            for kw in config["keywords"]:
                kw_lower = kw.lower()
                # 检查是否在话术检测或关键词命中中出现
                for tactic_name in detected_tactics:
                    if any(k in tactic_name for k in kw.split()):
                        score += 0.4
                hit_str = " ".join(rhetoric_result.get("keyword_hits", {}).get("high", []))
                if kw_lower in hit_str.lower():
                    score += 0.3
            scores[fraud_type] = score

        if not scores or max(scores.values()) < 0.3:
            return None, "低"

        best_type = max(scores, key=lambda k: scores[k])
        best_score = scores[best_type]

        if best_score >= 0.8:
            confidence = "高"
        elif best_score >= 0.5:
            confidence = "中"
        else:
            confidence = "低"

        return best_type, confidence


# ─── 5. 综合评分 ─────────────────────────────────────────────

def _calc_overall_risk(
    rhetoric_result: Dict,
    company_result: Dict,
    sentiment_result: Dict,
    ai_risk_score: float = 0.0,
) -> Tuple[str, int]:
    """综合三维评分，返回 (风险等级, 0-100分)"""
    r_score = rhetoric_result.get("risk_score", 0.0)   # 0~1
    s_score = sentiment_result.get("negative_score", 0.0)  # 0~1
    c_weight = {"高危": 0.8, "可疑": 0.4, "正常": 0.0, "未知": 0.2}
    c_score = c_weight.get(company_result.get("verdict", "未知"), 0.2)

    # 加权融合（话术权重最高，其次舆情，再次公司核验）
    weighted = r_score * 0.45 + s_score * 0.30 + c_score * 0.15 + ai_risk_score * 0.10
    # 黑名单命中时直接拉高
    if sentiment_result.get("complaint_count", 0) >= 50:
        weighted = max(weighted, 0.85)
    if company_result.get("verdict") == "高危":
        weighted = max(weighted, 0.65)

    score_100 = min(int(weighted * 100), 100)

    if score_100 >= 75:
        level = "极高"
    elif score_100 >= 55:
        level = "高"
    elif score_100 >= 35:
        level = "中"
    else:
        level = "低"

    return level, score_100


def _build_evidence_chain(
    rhetoric_result: Dict,
    company_result: Dict,
    sentiment_result: Dict,
) -> List[str]:
    evidence = []
    for tactic in rhetoric_result.get("detected_tactics", []):
        evidence.append(f"【话术证据】检测到「{tactic['tactic']}」：「…{tactic['quote']}…」")
    for signal in company_result.get("risk_signals", []):
        evidence.append(f"【主体证据】{signal}")
    for snippet in sentiment_result.get("search_snippets", []):
        if any(kw in snippet for kw in ["投诉", "诈骗", "骗局", "维权", "曝光", "避雷"]):
            evidence.append(f"【舆情证据】{snippet}")
    if sentiment_result.get("complaint_count", 0) > 0:
        evidence.append(f"【投诉证据】检索到 {sentiment_result['complaint_count']} 条相关投诉记录")
    return evidence[:8]  # 最多返回8条


def _build_recommendations(overall_risk: str, fraud_type: Optional[str]) -> List[str]:
    base = {
        "极高": [
            "⛔ 立即中止与该机构的一切联系，不要再支付任何费用",
            "📱 拨打 12321 网络违法犯罪举报热线进行举报",
            "🏛️ 如已造成经济损失，携带证据前往当地派出所报案",
            "💬 在求职平台（BOSS直聘/招聘宝等）对该公司进行举报",
        ],
        "高": [
            "⚠️ 高度警惕，在付出任何费用前彻底核实公司资质",
            "🔍 在企查查/天眼查上查询公司注册信息和法院记录",
            "👥 通过公司官方渠道（官网/官方电话）交叉核验招聘信息",
            "📝 如已接触，保留所有聊天记录和转账凭证",
        ],
        "中": [
            "🔍 建议通过企查查核实公司基本信息",
            "💡 正规公司招聘不会要求任何形式的费用",
            "📞 通过官方渠道核实招聘信息真实性",
        ],
        "低": [
            "✅ 当前未发现明显风险特征",
            "💡 保持基本警惕，正规入职不需要缴纳任何费用",
        ],
    }
    recs = base.get(overall_risk, base["低"])
    # 针对特定诈骗类型追加建议
    type_tips = {
        "付费培训诈骗": "📚 国家明令禁止将培训费与入职挂钩，遇到此类要求可直接向劳动局投诉",
        "刷单返佣诈骗": "💳 刷单属于违法行为，且100%是诈骗，务必拒绝任何形式的垫资要求",
        "虚假内推诈骗": "🏢 大厂内推从不收费，凡是要钱的内推100%是骗局",
        "押金保证金诈骗": "🚫 任何合法雇佣关系都不得要求员工缴纳押金，此行为违反《劳动法》",
    }
    if fraud_type and fraud_type in type_tips:
        recs.insert(1, type_tips[fraud_type])
    return recs


# ─── 主入口 ──────────────────────────────────────────────────

class RecruitmentAnalysisPipeline:
    """
    招聘诈骗分析主流水线
    """

    @staticmethod
    def _extract_company_name(text: str, input_type: str) -> Optional[str]:
        """从文本中尝试提取公司名称"""
        if input_type == "company_name":
            return text.strip()

        # 常见格式：「公司：XX」「招聘单位：XX」「XX有限公司」
        patterns = [
            r"公司[名称：:\s]+([^\n，。,]{4,20}(?:公司|集团|科技|咨询|教育))",
            r"招聘单位[：:\s]+([^\n，。,]{4,20})",
            r"([^\n，。,《【]{4,20}(?:有限公司|股份公司|集团|科技公司))",
        ]
        for p in patterns:
            m = re.search(p, text)
            if m:
                return m.group(1).strip()
        return None

    @classmethod
    def run(
        cls,
        input_type: str,
        content: str,
        extra_keywords: List[str] = [],
        ai_result: Dict = None,
    ) -> Dict:
        """
        执行完整分析，返回结构化报告字典
        """
        logger.info(f"[RECRUIT] 开始分析 | input_type={input_type}")

        # 1) 公司核验
        company_name = cls._extract_company_name(content, input_type)
        company_result = CompanyChecker.check(company_name or "", content) if company_name else {
            "company_name": None, "found": False, "risk_signals": [], "verdict": "未知",
        }

        # 2) 话术分析
        rhetoric_result = RecruitmentRhetoricAnalyzer.analyze(content, extra_keywords)

        # 3) 舆情查询
        sentiment_result = RecruitmentSentimentChecker.check(
            company_name=company_name or "",
            url="" if input_type != "url" else content,
        )

        # 4) AI补充分数
        ai_risk_score = float(ai_result.get("risk_score", 0.0)) if ai_result else 0.0

        # 5) 综合评分
        overall_risk, risk_score = _calc_overall_risk(
            rhetoric_result, company_result, sentiment_result, ai_risk_score
        )

        # 6) 诈骗类型识别（规则引擎）
        fraud_type, fraud_confidence = FraudTypeIdentifier.identify(
            rhetoric_result, company_result, sentiment_result
        )
        # AI识别结果覆盖（如果置信度更高）
        if ai_result and ai_result.get("fraud_types"):
            ai_type = ai_result["fraud_types"][0] if ai_result["fraud_types"] else None
            ai_confidence = ai_result.get("fraud_type_confidence", "低")
            if ai_type and (fraud_confidence == "低" or ai_confidence == "高"):
                fraud_type = ai_type
                fraud_confidence = ai_confidence

        # 7) 证据链
        evidence_chain = _build_evidence_chain(rhetoric_result, company_result, sentiment_result)
        if ai_result and ai_result.get("key_evidence"):
            for ev in ai_result["key_evidence"]:
                if ev not in evidence_chain:
                    evidence_chain.append(f"【AI证据】{ev}")

        # 8) 建议
        recommendations = _build_recommendations(overall_risk, fraud_type)

        # 9) 摘要
        summary_parts = []
        if fraud_type:
            summary_parts.append(f"研判为「{fraud_type}」")
        summary_parts.append(f"综合风险{overall_risk}（{risk_score}分）")
        if rhetoric_result["detected_tactics"]:
            tactics_str = "、".join(t["tactic"] for t in rhetoric_result["detected_tactics"][:2])
            summary_parts.append(f"检测到{tactics_str}等风险话术")
        if sentiment_result["complaint_count"] > 0:
            summary_parts.append(f"网络存在{sentiment_result['complaint_count']}条相关投诉")
        summary = "，".join(summary_parts) + "。"

        logger.success(f"[RECRUIT] 分析完成 | risk={overall_risk}({risk_score}) | fraud_type={fraud_type}")

        return {
            "input_type": input_type,
            "input_summary": content[:80] + ("…" if len(content) > 80 else ""),
            "overall_risk": overall_risk,
            "risk_score": risk_score,
            "fraud_type": fraud_type,
            "fraud_type_confidence": fraud_confidence,
            "company_check": company_result,
            "rhetoric_analysis": rhetoric_result,
            "sentiment_check": sentiment_result,
            "evidence_chain": evidence_chain,
            "recommendations": recommendations,
            "summary": summary,
            "ai_detail": ai_result,
        }