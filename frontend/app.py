# frontend/app.py
"""
涉诈智能研判系统 v2.0 — Streamlit 前端
新增：招聘诈骗研判 / 涉诈信息库 / 反诈预警
保留：原有涉诈网站 URL 分析功能
"""
import streamlit as st
import asyncio
import sys
import os
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Streamlit Cloud Secrets → 环境变量
for _key in ["GEMINI_API_KEY", "DEEPSEEK_API_KEY"]:
    try:
        os.environ[_key] = st.secrets[_key]
    except Exception:
        pass

st.set_page_config(
    page_title="涉诈智能研判系统 v2.0",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── 全局样式 ────────────────────────────────────────────────
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@300;400;600;700&family=Share+Tech+Mono&display=swap');
  html, body, [class*="css"] { font-family: 'Noto Sans SC', sans-serif; }

  /* 风险卡片 */
  .risk-card-RED    { background:linear-gradient(135deg,#2d0a0a,#1a0505); border-left:4px solid #f44336; }
  .risk-card-ORANGE { background:linear-gradient(135deg,#2d1a0a,#1a0d05); border-left:4px solid #ff9800; }
  .risk-card-YELLOW { background:linear-gradient(135deg,#2d2a0a,#1a1805); border-left:4px solid #ffeb3b; }
  .risk-card-GREEN  { background:linear-gradient(135deg,#0a2d0a,#051a05); border-left:4px solid #4caf50; }
  .risk-card-极高   { background:linear-gradient(135deg,#2d0a0a,#1a0505); border-left:4px solid #f44336; }
  .risk-card-高     { background:linear-gradient(135deg,#2d1a0a,#1a0d05); border-left:4px solid #ff9800; }
  .risk-card-中     { background:linear-gradient(135deg,#2d2a0a,#1a1805); border-left:4px solid #ffeb3b; }
  .risk-card-低     { background:linear-gradient(135deg,#0a2d0a,#051a05); border-left:4px solid #4caf50; }
  .risk-card { padding:20px 24px; border-radius:8px; margin:16px 0; }
  .risk-score-big { font-size:64px; font-weight:700; font-family:'Share Tech Mono',monospace; line-height:1; }

  /* 情报列表 */
  .intel-item { display:flex; justify-content:space-between; padding:8px 12px; border-bottom:1px solid #1e2d3d; font-size:13px; }
  .intel-key { color:#546e7a; font-family:'Share Tech Mono',monospace; }
  .intel-val { color:#eceff1; text-align:right; max-width:60%; word-break:break-all; }

  /* 特征进度条 */
  .feat-bar-bg { background:#1e2d3d; border-radius:3px; height:8px; margin-top:3px; }

  /* 关键词标签 */
  .kw-tag-high   { background:#3d0000;color:#ef9a9a;border:1px solid #b71c1c;padding:2px 8px;border-radius:12px;font-size:11px;margin:2px;display:inline-block; }
  .kw-tag-medium { background:#3d2000;color:#ffcc80;border:1px solid #e65100;padding:2px 8px;border-radius:12px;font-size:11px;margin:2px;display:inline-block; }
  .kw-tag-low    { background:#3d3d00;color:#fff176;border:1px solid #f9a825;padding:2px 8px;border-radius:12px;font-size:11px;margin:2px;display:inline-block; }

  /* 处置步骤 */
  .step-item { display:flex; align-items:flex-start; margin:10px 0; padding:8px 12px; background:#0a1628; border-radius:4px; font-size:14px; color:#b0bec5; }

  /* 话术标签 */
  .tactic-high   { background:#3d0000;color:#ef9a9a;border:1px solid #b71c1c;padding:4px 10px;border-radius:6px;font-size:12px;margin:3px;display:inline-block; }
  .tactic-medium { background:#3d2000;color:#ffcc80;border:1px solid #e65100;padding:4px 10px;border-radius:6px;font-size:12px;margin:3px;display:inline-block; }

  /* 证据链 */
  .evidence-item { display:flex; gap:12px; align-items:flex-start; margin:8px 0; padding:10px 14px; background:#0a1628; border-radius:6px; border-left:3px solid #37474f; font-size:13px; color:#b0bec5; }

  /* 数据库记录卡 */
  .db-record { background:#0d1b2a; border:1px solid #1e3a5f; border-radius:8px; padding:14px 18px; margin:8px 0; }

  /* 反诈统计 */
  .stat-card { background:#0d1b2a; border:1px solid #1e3a5f; border-radius:8px; padding:16px; text-align:center; }
  .stat-num  { font-size:32px; font-weight:700; font-family:'Share Tech Mono',monospace; }
</style>
""", unsafe_allow_html=True)


# ─── 顶部标题 ────────────────────────────────────────────────
st.markdown("""
<div style="background:linear-gradient(135deg,#0d1b2a,#1a2744);border:1px solid #1e3a5f;border-radius:8px;padding:18px 28px;margin-bottom:20px;">
  <div style="font-size:20px;font-weight:700;color:#4fc3f7;letter-spacing:2px;">
    🛡️ 涉诈智能研判与决策支持系统 v2.0
  </div>
  <div style="font-size:11px;color:#546e7a;margin-top:4px;font-family:'Share Tech Mono',monospace;">
    OSINT-BASED FRAUD INTELLIGENCE SYSTEM | 涉诈网站研判 · 招聘诈骗识别 · 信息库 · 反诈预警 | 仅限授权人员
  </div>
</div>
""", unsafe_allow_html=True)


# ─── 侧边栏 ──────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### ⚙️ 分析参数")
    analyst_id = st.text_input("分析员工号", placeholder="如：P20240001")
    priority   = st.selectbox("任务优先级", ["normal", "urgent"])
    extra_kw   = st.text_area("补充风险关键词（每行一个）", height=80)
    extra_keywords = [k.strip() for k in extra_kw.splitlines() if k.strip()]

    st.markdown("---\n### 🤖 AI 引擎")
    _gk = os.getenv("GEMINI_API_KEY", "")
    _dk = os.getenv("DEEPSEEK_API_KEY", "")
    _engine_opts = {"自动（Gemini优先）": "auto", "仅 Gemini": "gemini", "仅 DeepSeek": "deepseek"}
    _engine_label = st.radio("AI 引擎", list(_engine_opts.keys()))
    ai_engine = _engine_opts[_engine_label]

    if ai_engine == "auto" and not _gk and not _dk:
        st.warning("AI 未配置，将使用规则引擎分析")
    elif _gk or _dk:
        st.success(f"✦ {'Gemini✓' if _gk else ''} {'DeepSeek✓' if _dk else ''}")

    st.markdown("---\n### 📋 风险等级")
    st.markdown("""
🔴 **极高 / RED** ≥75 — 立即处置  
🟠 **高 / ORANGE** 55~74 — 重点监控  
🟡 **中 / YELLOW** 35~54 — 继续侦查  
🟢 **低 / GREEN** <35 — 存档备查
    """)

    st.markdown("---\n### 🧪 快速测试（招聘诈骗）")
    demo_cases = {
        "付费培训诈骗示例": "岗位：Java实习生 | 薪资：入职后月薪1万5，需先参加公司3800元培训课程，结业后100%推荐就业，名额有限请尽快缴费。",
        "虚假内推示例":     "同学你好，我是腾讯内部HR，现有内部推荐名额可绕过笔试直接面试，需先缴纳500元保证金，三个工作日内退还。",
        "刷单返佣示例":     "诚招兼职刷手，每单佣金5~30元，先垫付购买商品后平台返款，无需任何经验，日结工资，急招100名。",
    }
    for label, demo_text in demo_cases.items():
        if st.button(label, use_container_width=True):
            st.session_state["recruit_input"] = demo_text
            st.session_state["recruit_type"] = "recruitment_text"


# ─── 主 Tab 导航 ─────────────────────────────────────────────
tab_url, tab_recruit, tab_db, tab_aware = st.tabs([
    "🌐 涉诈网站研判",
    "💼 招聘诈骗识别",
    "🗄️ 涉诈信息库",
    "📡 反诈预警"
])


# ═══════════════════════════════════════════════════════════════
# Tab 1：原有涉诈网站 URL 分析（完整保留）
# ═══════════════════════════════════════════════════════════════
with tab_url:
    def risk_color(level):
        return {"RED":"#f44336","ORANGE":"#ff9800","YELLOW":"#ffeb3b","GREEN":"#4caf50"}.get(level,"#90a4ae")
    def risk_emoji(level):
        return {"RED":"🔴","ORANGE":"🟠","YELLOW":"🟡","GREEN":"🟢"}.get(level,"⚪")
    def render_bar(name, value, contrib):
        pct = int(value * 100)
        color = "#f44336" if value>0.7 else ("#ff9800" if value>0.4 else ("#ffeb3b" if value>0.2 else "#4caf50"))
        st.markdown(f"""<div style="margin:6px 0"><div style="display:flex;justify-content:space-between"><span style="font-size:12px;color:#78909c;font-family:'Share Tech Mono',monospace">{name}</span><span style="font-size:11px;color:#90a4ae">{pct}%  贡献:{contrib:.2f}分</span></div><div class="feat-bar-bg"><div style="background:{color};height:8px;border-radius:3px;width:{pct}%"></div></div></div>""", unsafe_allow_html=True)

    col_input, col_btn = st.columns([4, 1])
    with col_input:
        url_input = st.text_input("", value=st.session_state.get("target_url",""),
            placeholder="输入目标网址，如：suspicious-invest.com", label_visibility="collapsed")
    with col_btn:
        analyze_url_btn = st.button("▶ 开始研判", use_container_width=True, key="url_btn")

    # 快速测试按钮行
    c1, c2, c3 = st.columns(3)
    with c1:
        if st.button("模拟高危投资诈骗", use_container_width=True):
            st.session_state["target_url"] = "quick-profit.xyz"
    with c2:
        if st.button("模拟境外赌博平台", use_container_width=True):
            st.session_state["target_url"] = "bet-win-now.top"
    with c3:
        if st.button("模拟正常政府网站", use_container_width=True):
            st.session_state["target_url"] = "www.beijing.gov.cn"

    if analyze_url_btn and url_input.strip():
        with st.spinner("🔄 正在执行多维度情报采集与研判分析..."):
            try:
                from backend.modules.pipeline import AnalysisPipeline
                from backend.models.schemas import AnalysisRequest
                request = AnalysisRequest(
                    url=url_input.strip(), priority=priority,
                    analyst_id=analyst_id or None,
                    extra_keywords=extra_keywords, ai_engine=ai_engine,
                )
                pipeline = AnalysisPipeline()
                loop = asyncio.new_event_loop()
                result = loop.run_until_complete(pipeline.run(request))
                loop.close()
            except Exception as e:
                st.error(f"分析失败：{e}")
                st.stop()

        if not result.success:
            st.error(f"❌ 分析异常：{result.error}")
            st.stop()

        report = result.report
        if not report:
            st.error("❌ 报告数据为空")
            st.stop()
        wras = report.wras
        intel = report.raw_intel
        feat  = report.features

        st.markdown(f"""<div class="risk-card risk-card-{wras.risk_level.value}">
          <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;">
            <div>
              <div style="font-size:13px;color:#90a4ae;letter-spacing:1px;">综合风险评分</div>
              <div class="risk-score-big" style="color:{risk_color(wras.risk_level.value)}">{wras.final_score:.1f}</div>
              <div style="font-size:14px;color:#90a4ae;margin-top:8px">{risk_emoji(wras.risk_level.value)} {report.disposal.level} | 置信度 {wras.confidence_coeff:.0%} | {report.report_id}</div>
            </div>
            <div style="text-align:right">
              <div style="font-size:12px;color:#546e7a">原始分 × 置信度</div>
              <div style="font-family:'Share Tech Mono',monospace;color:#90a4ae;font-size:18px">{wras.raw_score:.1f} × {wras.confidence_coeff:.3f}</div>
              <div style="font-size:11px;color:#37474f;margin-top:8px">分析耗时: {result.elapsed_s:.1f}s</div>
            </div>
          </div>
        </div>""", unsafe_allow_html=True)

        FEAT_LABELS = {
            "domain_age_days":"域名注册时长","icp_missing":"ICP备案缺失",
            "whois_privacy_protected":"WHOIS信息隐藏","ssl_self_signed":"SSL证书异常",
            "ip_overseas":"服务器境外","ip_cdn_abuse":"CDN规避行为",
            "keyword_risk_score":"风险话术密度","phishing_visual_sim":"钓鱼仿冒相似度",
            "resource_load_anomaly":"页面资源异常率","public_sentiment_neg":"负面舆情强度",
            "complaint_count_norm":"投诉量归一化","blacklist_hit":"黑名单命中",
        }
        gemini = getattr(report, "gemini", None)
        t1, t2, t3, t4, t5 = st.tabs(["📊 风险热力图","🔍 原始情报","⚖️ 处置预案","🤖 AI 分析","📄 完整报告"])

        with t1:
            ca, cb = st.columns(2)
            fd = feat.model_dump()
            items = [(k,v) for k,v in fd.items() if isinstance(v,(int,float))]
            half = len(items)//2
            with ca:
                st.markdown("**域名 · 网络维度**")
                for k,v in items[:half]:
                    render_bar(FEAT_LABELS.get(k,k), v, wras.feature_contrib.get(k,0.0))
            with cb:
                st.markdown("**内容 · 舆情维度**")
                for k,v in items[half:]:
                    render_bar(FEAT_LABELS.get(k,k), v, wras.feature_contrib.get(k,0.0))
            st.markdown("---\n**各维度得分汇总**")
            cols = st.columns(len(wras.score_breakdown))
            for col, (dim, score) in zip(cols, wras.score_breakdown.items()):
                c = "#f44336" if score>20 else ("#ff9800" if score>12 else ("#ffeb3b" if score>6 else "#4caf50"))
                with col:
                    st.markdown(f"""<div style="text-align:center;padding:12px;background:#0d1b2a;border-radius:6px;border:1px solid #1e3a5f">
                      <div style="font-size:24px;font-weight:700;color:{c};font-family:'Share Tech Mono',monospace">{score:.1f}</div>
                      <div style="font-size:11px;color:#546e7a;margin-top:4px">{dim}</div></div>""", unsafe_allow_html=True)
            if any(feat.keyword_hits.values()):
                st.markdown("---\n**⚠️ 命中风险关键词**")
                for level, words in feat.keyword_hits.items():
                    if words:
                        st.markdown(" ".join(f'<span class="kw-tag-{level}">{w}</span>' for w in words), unsafe_allow_html=True)

        with t2:
            cl, cr = st.columns(2)
            with cl:
                st.markdown("**📋 域名 / 注册信息**")
                for k,v in [("目标域名",intel.domain),("域名注册天数",f"{intel.domain_age_days or '未知'} 天"),
                             ("注册商",intel.registrar or "未知"),("WHOIS隐私","⚠️ 是" if intel.whois_privacy else "否"),
                             ("ICP备案",intel.icp_record or "⚠️ 无备案"),("SSL证书","有效" if intel.ssl_valid else "⚠️ 无效"),
                             ("自签名","⚠️ 是" if intel.ssl_self_signed else "否")]:
                    st.markdown(f'<div class="intel-item"><span class="intel-key">{k}</span><span class="intel-val">{v}</span></div>', unsafe_allow_html=True)
            with cr:
                st.markdown("**🌐 服务器 / 网络信息**")
                for k,v in [("服务器IP",intel.server_ip or "—"),("所在国家",intel.server_country or "未知"),
                             ("CDN使用","⚠️ 是" if intel.is_cdn else "否"),("跳转链路",f"{len(intel.redirect_chain)} 跳"),
                             ("黑名单命中","⚠️ 是" if intel.blacklist_hit else "否"),("投诉量",f"{intel.complaint_count} 条")]:
                    st.markdown(f'<div class="intel-item"><span class="intel-key">{k}</span><span class="intel-val">{v}</span></div>', unsafe_allow_html=True)
                if intel.search_snippets:
                    st.markdown("**舆情摘要**")
                    for s in intel.search_snippets:
                        st.markdown(f"> {s}")

        with t3:
            rc = risk_color(wras.risk_level.value)
            st.markdown(f"""<div style="background:#0d1b2a;border:1px solid #1e3a5f;border-radius:8px;padding:20px">
              <div style="font-size:18px;font-weight:700;color:{rc}">{risk_emoji(wras.risk_level.value)} {report.disposal.level}</div>
              <div style="color:#b0bec5;margin-top:8px">{report.disposal.action}</div></div>""", unsafe_allow_html=True)
            st.markdown("**📌 处置步骤**")
            for i, step in enumerate(report.disposal.steps, 1):
                st.markdown(f'<div class="step-item"><span style="color:{rc};font-weight:700;margin-right:12px">{i}</span><span>{step}</span></div>', unsafe_allow_html=True)

        with t4:
            if gemini:
                st.markdown(f"**✦ {gemini.model_name}** — 耗时 {gemini.ai_elapsed_s:.1f}s")
                st.markdown("### 🧠 AI 内容语义分析")
                ai_score = gemini.content_risk_score
                ai_color = "#f44336" if ai_score>0.7 else ("#ff9800" if ai_score>0.4 else "#4caf50")
                st.markdown(f"""<div style="background:#0d1b2a;border:1px solid #1e3a5f;border-radius:8px;padding:16px">
                  <div style="font-size:36px;font-weight:700;color:{ai_color};font-family:'Share Tech Mono',monospace">{ai_score:.0%}</div>
                  <div style="color:#b0bec5;font-size:13px;margin-top:6px">{gemini.content_reasoning}</div></div>""", unsafe_allow_html=True)
                if gemini.fraud_types:
                    st.markdown(" ".join(f'<span class="kw-tag-high">{ft}</span>' for ft in gemini.fraud_types), unsafe_allow_html=True)
                if gemini.ai_report:
                    st.markdown("---\n### 📝 AI 侦查报告")
                    st.markdown(gemini.ai_report)
            else:
                st.info("⚠️ AI 引擎未配置，请设置 GEMINI_API_KEY 或 DEEPSEEK_API_KEY")

        with t5:
            report_dict = {"report_id":report.report_id,"url":report.url,"wras_score":wras.final_score,"risk_level":wras.risk_level.value}
            st.json(report_dict)
            st.download_button("⬇ 下载 JSON 报告", data=json.dumps(report_dict, ensure_ascii=False, indent=2),
                file_name=f"{report.report_id}.json", mime="application/json")

    elif analyze_url_btn:
        st.warning("⚠️ 请输入目标网址")


# ═══════════════════════════════════════════════════════════════
# Tab 2：招聘诈骗识别（新增）
# ═══════════════════════════════════════════════════════════════
with tab_recruit:
    # 辅助函数
    def r_color(level):
        return {"极高":"#f44336","高":"#ff9800","中":"#ffeb3b","低":"#4caf50",
                "高危":"#f44336","可疑":"#ff9800","正常":"#4caf50","未知":"#78909c"}.get(level,"#78909c")
    def r_emoji(level):
        return {"极高":"🔴","高":"🟠","中":"🟡","低":"🟢",
                "高危":"🔴","可疑":"🟠","正常":"🟢","未知":"⚪"}.get(level,"⚪")

    # 输入区
    INPUT_TYPES = {
        "recruitment_text": "📄 招聘信息",
        "chat_log":         "💬 聊天记录",
        "company_name":     "🏢 公司名称",
        "url":              "🔗 相关链接",
    }
    PLACEHOLDERS = {
        "recruitment_text": "粘贴完整招聘信息，包含岗位名称、薪资、要求、投递方式等…",
        "chat_log":         "粘贴与招聘方的完整聊天记录…",
        "company_name":     "输入公司全称，如：XX科技（上海）有限公司",
        "url":              "粘贴招聘帖链接、公司官网或相关帖子URL…",
    }

    input_type_sel = st.radio(
        "输入类型",
        list(INPUT_TYPES.keys()),
        format_func=lambda k: INPUT_TYPES[k],
        horizontal=True,
        key="recruit_type",
    )
    content_input = st.text_area(
        "",
        value=st.session_state.get("recruit_input", ""),
        placeholder=PLACEHOLDERS[input_type_sel],
        height=160,
        label_visibility="collapsed",
        key="recruit_content",
    )

    col_a, col_b = st.columns([3, 1])
    with col_b:
        save_to_db = st.checkbox("📥 分析后存入信息库", value=False)
    with col_a:
        analyze_recruit_btn = st.button("🔍 启动三维风险分析", use_container_width=True, key="recruit_btn",
            type="primary" if content_input.strip() else "secondary",
            disabled=not content_input.strip())

    if analyze_recruit_btn and content_input.strip():
        with st.spinner("🔄 正在进行公司核验 / 话术分析 / 舆情研判…"):
            try:
                from backend.modules.recruitment_analyzer import RecruitmentAnalysisPipeline

                # 若AI可用，先做AI分析
                ai_result = None
                if _gk or _dk:
                    try:
                        from backend.modules.gemini_analyzer import RecruitmentFraudAnalyzer
                        ai_result = RecruitmentFraudAnalyzer.analyze(
                            content_input.strip(), input_type_sel, engine=ai_engine
                        )
                    except Exception as ai_e:
                        st.warning(f"AI分析失败（降级规则引擎）: {ai_e}")

                report = RecruitmentAnalysisPipeline.run(
                    input_type=input_type_sel,
                    content=content_input.strip(),
                    extra_keywords=extra_keywords,
                    ai_result=ai_result,
                )

                # 存入信息库
                if save_to_db and report["overall_risk"] in ("极高", "高"):
                    from backend.modules.fraud_database import add_record
                    import re as _re
                    company_name = report.get("company_check", {}).get("company_name") or ""
                    kw_hits = report.get("rhetoric_analysis", {}).get("keyword_hits", {})
                    all_kw = kw_hits.get("high", [])[:5]
                    add_record({
                        "company": company_name,
                        "url": content_input.strip()[:100] if input_type_sel == "url" else None,
                        "input_type": input_type_sel,
                        "fraud_type": report.get("fraud_type"),
                        "risk_level": report["overall_risk"],
                        "risk_score": report["risk_score"],
                        "evidence": report.get("evidence_chain", [])[:3],
                        "complaint_count": report.get("sentiment_check", {}).get("complaint_count", 0),
                        "analyst_id": analyst_id or None,
                    })
                    st.success("✅ 已录入涉诈信息库")

            except Exception as e:
                st.error(f"分析失败：{e}")
                import traceback; st.code(traceback.format_exc())
                st.stop()

        # ── 综合风险总览卡 ──────────────────────────────────────
        overall = report["overall_risk"]
        score   = report["risk_score"]
        fraud_type = report.get("fraud_type")
        col_score, col_meta = st.columns([1, 3])
        with col_score:
            st.markdown(f"""<div class="risk-card risk-card-{overall}" style="text-align:center;padding:24px 16px;">
              <div style="font-size:11px;color:#90a4ae;letter-spacing:2px;margin-bottom:6px;">综合风险评分</div>
              <div class="risk-score-big" style="color:{r_color(overall)}">{score}</div>
              <div style="margin-top:8px">{r_emoji(overall)} <span style="color:{r_color(overall)};font-weight:700;font-size:15px">{overall}风险</span></div>
            </div>""", unsafe_allow_html=True)
        with col_meta:
            st.markdown(f"""<div style="background:#0d1b2a;border:1px solid #1e3a5f;border-radius:8px;padding:16px 20px;height:100%;box-sizing:border-box;">
              {'<div style="margin-bottom:10px"><span style="background:#5c0099;color:#e040fb;border:1px solid #7b1fa2;padding:3px 12px;border-radius:12px;font-size:13px;font-weight:700;">🎯 ' + fraud_type + '</span><span style="color:#546e7a;font-size:11px;margin-left:8px;">识别置信度：' + report.get("fraud_type_confidence","低") + '</span></div>' if fraud_type else ''}
              <div style="color:#b0bec5;font-size:14px;line-height:1.8">{report["summary"]}</div>
            </div>""", unsafe_allow_html=True)

        # ── 三维研判 Tab ────────────────────────────────────────
        sub1, sub2, sub3, sub4, sub5 = st.tabs([
            "🏢 主体核验", "🗣️ 话术分析", "📊 舆情判断", "🔗 证据链", "💡 建议与处置"
        ])

        with sub1:
            cc = report.get("company_check", {})
            verdict = cc.get("verdict", "未知")
            st.markdown(f"""<div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;">
              <span style="font-size:24px">{r_emoji(verdict)}</span>
              <div><div style="font-weight:700;font-size:16px;color:{r_color(verdict)}">{cc.get('company_name','未识别到公司名称')}</div>
              <div style="color:#546e7a;font-size:13px">主体核验：{verdict}</div></div>
            </div>""", unsafe_allow_html=True)

            for k, v in [
                ("核验状态", "✅ 已找到" if cc.get("found") else "❓ 未在库中找到"),
                ("注册状态", cc.get("registration_status") or "—"),
                ("成立年限", f"{cc.get('established_years')} 年" if cc.get('established_years') else "—"),
                ("注册资本", cc.get("registered_capital") or "—"),
                ("ICP 备案", cc.get("icp_record") or "⚠️ 无备案"),
            ]:
                st.markdown(f'<div class="intel-item"><span class="intel-key">{k}</span><span class="intel-val">{v}</span></div>', unsafe_allow_html=True)

            if cc.get("risk_signals"):
                st.markdown("**⚡ 风险信号**")
                for sig in cc["risk_signals"]:
                    st.markdown(f'<div style="padding:6px 12px;background:#3d0000;border-left:3px solid #f44336;border-radius:4px;margin:4px 0;font-size:13px;color:#ef9a9a;">⚠️ {sig}</div>', unsafe_allow_html=True)
            else:
                st.info("未发现明显主体风险信号")

        with sub2:
            ra = report.get("rhetoric_analysis", {})
            tactics = ra.get("detected_tactics", [])
            r_score  = ra.get("risk_score", 0.0)
            verdict_r = ra.get("verdict", "正常")

            col_rv, col_rbar = st.columns([1, 3])
            with col_rv:
                pct = int(r_score * 100)
                bar_color = r_color(verdict_r)
                st.markdown(f"""<div style="background:#0d1b2a;border:1px solid #1e3a5f;border-radius:8px;padding:16px;text-align:center">
                  <div style="font-size:28px;font-weight:700;color:{bar_color};font-family:'Share Tech Mono',monospace">{pct}%</div>
                  <div style="font-size:12px;color:#546e7a;margin-top:4px">话术风险指数</div>
                  <div style="margin-top:8px">{r_emoji(verdict_r)} <span style="color:{bar_color}">{verdict_r}</span></div>
                </div>""", unsafe_allow_html=True)
            with col_rbar:
                if tactics:
                    st.markdown(f"**检测到 {len(tactics)} 个风险话术**")
                    for t in tactics:
                        sev = t.get("severity","中")
                        css_cls = "tactic-high" if sev == "高" else "tactic-medium"
                        st.markdown(f"""<div style="background:#0a1628;border:1px solid #1e3a5f;border-radius:6px;padding:10px 14px;margin:6px 0;">
                          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                            <span class="{css_cls}">🚩 {t.get('tactic','')}</span>
                            <span style="color:#546e7a;font-size:11px">{sev}风险</span>
                          </div>
                          <div style="color:#78909c;font-size:12px;font-style:italic">「…{t.get('quote','')}…」</div>
                        </div>""", unsafe_allow_html=True)
                else:
                    st.success("✅ 未检测到明显风险话术")

            kw_hits = ra.get("keyword_hits", {})
            if any(kw_hits.values()):
                st.markdown("**命中关键词**")
                for level, words in kw_hits.items():
                    if words:
                        st.markdown(" ".join(f'<span class="kw-tag-{level}">{w}</span>' for w in words), unsafe_allow_html=True)

        with sub3:
            sc = report.get("sentiment_check", {})
            verdict_s = sc.get("verdict", "正常")
            neg = sc.get("negative_score", 0.0)
            complaints = sc.get("complaint_count", 0)

            col_s1, col_s2, col_s3 = st.columns(3)
            for col, label, value, unit in [
                (col_s1, "舆情风险指数", f"{int(neg*100)}%", ""),
                (col_s2, "相关投诉记录", str(complaints), "条"),
                (col_s3, "综合判定", r_emoji(verdict_s) + " " + verdict_s, ""),
            ]:
                vcolor = r_color(verdict_s) if label != "相关投诉记录" else ("#f44336" if complaints >= 20 else "#4caf50")
                with col:
                    st.markdown(f"""<div class="stat-card">
                      <div class="stat-num" style="color:{vcolor}">{value}</div>
                      <div style="color:#546e7a;font-size:12px;margin-top:4px">{label}</div>
                    </div>""", unsafe_allow_html=True)

            if sc.get("search_snippets"):
                st.markdown("**🔎 相关网络舆情**")
                for snippet in sc["search_snippets"]:
                    has_neg = any(kw in snippet for kw in ["投诉","诈骗","骗局","维权","曝光","避雷","被骗"])
                    border_color = "#b71c1c" if has_neg else "#1e3a5f"
                    st.markdown(f'<div style="padding:8px 14px;border-left:3px solid {border_color};background:#0a1628;margin:5px 0;font-size:13px;color:#b0bec5;border-radius:0 6px 6px 0">{snippet}</div>', unsafe_allow_html=True)
            else:
                st.info("未检索到相关舆情信息")

        with sub4:
            evidence = report.get("evidence_chain", [])
            if evidence:
                st.markdown(f"**共 {len(evidence)} 条证据**")
                type_colors = {"【话术证据】":"#b71c1c","【主体证据】":"#1565c0","【舆情证据】":"#4a148c","【投诉证据】":"#bf360c","【AI证据】":"#1b5e20"}
                for i, ev in enumerate(evidence, 1):
                    ev_type = next((k for k in type_colors if ev.startswith(k)), "")
                    border = type_colors.get(ev_type, "#37474f")
                    st.markdown(f"""<div class="evidence-item" style="border-left-color:{border}">
                      <span style="color:{border};font-weight:700;min-width:20px">{i}</span>
                      <span>{ev}</span>
                    </div>""", unsafe_allow_html=True)
            else:
                st.info("暂无证据")

            if report.get("ai_detail") and report["ai_detail"].get("key_evidence"):
                st.markdown("**🤖 AI 提取的关键证据**")
                for ev in report["ai_detail"]["key_evidence"]:
                    st.markdown(f"- {ev}")

        with sub5:
            recs = report.get("recommendations", [])
            for rec in recs:
                icon = rec[0] if rec and rec[0] in "⛔⚠️🔍📱🏛️💬💡✅📝📚💳🏢🚫" else "→"
                st.markdown(f'<div style="display:flex;gap:10px;align-items:flex-start;padding:10px 14px;background:#0a1628;border-radius:6px;margin:6px 0;font-size:14px;color:#b0bec5;border-left:2px solid #1e3a5f">{rec}</div>', unsafe_allow_html=True)

            # AI侦查报告（如有）
            if report.get("ai_detail") and report["ai_detail"].get("_provider"):
                with st.expander(f"🤖 AI 深度分析报告 ({report['ai_detail']['_provider']})"):
                    st.markdown(f"**欺诈风险评分：** {report['ai_detail'].get('risk_score',0):.0%}")
                    st.markdown(f"**判断理由：** {report['ai_detail'].get('reasoning','—')}")
                    if report['ai_detail'].get('fraud_types'):
                        st.markdown("**识别到的诈骗类型：** " + "、".join(report['ai_detail']['fraud_types']))


# ═══════════════════════════════════════════════════════════════
# Tab 3：涉诈信息库
# ═══════════════════════════════════════════════════════════════
with tab_db:
    from backend.modules.fraud_database import get_all_records, search_records, add_record, get_stats

    # 搜索栏
    col_q, col_filter1, col_filter2 = st.columns([3, 1, 1])
    with col_q:
        db_query = st.text_input("", placeholder="搜索公司名、诈骗类型或关键词…", label_visibility="collapsed")
    with col_filter1:
        db_fraud_type = st.selectbox("诈骗类型", ["全部", "付费培训诈骗", "虚假内推诈骗", "刷单返佣诈骗", "押金保证金诈骗", "虚假高薪诈骗"])
    with col_filter2:
        db_risk_level = st.selectbox("风险等级", ["全部", "极高", "高", "中", "低"])

    results = search_records(
        query=db_query,
        fraud_type=db_fraud_type if db_fraud_type != "全部" else "",
        risk_level=db_risk_level if db_risk_level != "全部" else "",
    )

    st.markdown(f'<div style="color:#546e7a;font-size:13px;margin-bottom:12px">共找到 <span style="color:#4fc3f7;font-weight:700">{len(results)}</span> 条记录</div>', unsafe_allow_html=True)

    if results:
        for rec in results:
            risk  = rec.get("risk_level", "中")
            ft    = rec.get("fraud_type") or "未分类"
            score = rec.get("risk_score", 0)
            complaint = rec.get("complaint_count", 0)
            company = rec.get("company") or rec.get("url") or "未知主体"
            created = rec.get("created_at", "")[:10]
            evidence = rec.get("evidence", [])

            risk_col_map = {"极高":"#f44336","高":"#ff9800","中":"#ffeb3b","低":"#4caf50"}
            rc_color = risk_col_map.get(risk, "#78909c")

            st.markdown(f"""<div class="db-record">
              <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px;margin-bottom:10px;">
                <div>
                  <div style="font-size:15px;font-weight:700;color:#e8eaed">{company}</div>
                  <div style="margin-top:6px;display:flex;gap:8px;flex-wrap:wrap;">
                    <span style="background:{rc_color}22;color:{rc_color};border:1px solid {rc_color}66;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:700">{risk}风险</span>
                    <span style="background:#5c0099;color:#e040fb;border:1px solid #7b1fa2;padding:2px 10px;border-radius:12px;font-size:12px">{ft}</span>
                    <span style="background:#0d47a1;color:#82b1ff;border:1px solid #1565c0;padding:2px 10px;border-radius:12px;font-size:12px">{rec.get('input_type','—')}</span>
                  </div>
                </div>
                <div style="text-align:right">
                  <div style="font-size:26px;font-weight:800;color:{rc_color};font-family:'Share Tech Mono',monospace">{score}</div>
                  <div style="font-size:11px;color:#546e7a">评分</div>
                  <div style="font-size:11px;color:#f44336;margin-top:2px">投诉 {complaint} 条</div>
                </div>
              </div>
              <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:6px">
                {''.join(f'<span style="background:#3d0000;color:#ef9a9a;border:1px solid #b71c1c;padding:2px 8px;border-radius:6px;font-size:11px">⚡ {e}</span>' for e in evidence[:4])}
              </div>
              <div style="color:#37474f;font-size:11px">录入时间：{created} | ID：{rec.get('id','—')}</div>
            </div>""", unsafe_allow_html=True)
    else:
        st.markdown('<div style="text-align:center;padding:40px;color:#37474f">未找到匹配记录</div>', unsafe_allow_html=True)

    # 手动录入
    with st.expander("📝 手动录入新记录"):
        mn_col1, mn_col2 = st.columns(2)
        with mn_col1:
            mn_company = st.text_input("公司名称")
            mn_type = st.selectbox("诈骗类型", list({"付费培训诈骗","虚假内推诈骗","刷单返佣诈骗","押金保证金诈骗","虚假高薪诈骗","冒充猎头诈骗"}))
            mn_risk  = st.selectbox("风险等级", ["极高","高","中","低"])
        with mn_col2:
            mn_score = st.slider("风险评分", 0, 100, 60)
            mn_complaints = st.number_input("投诉量", min_value=0, value=0)
            mn_evidence = st.text_area("证据（每行一条）", height=80)
        if st.button("录入", type="primary"):
            add_record({
                "company": mn_company,
                "fraud_type": mn_type,
                "risk_level": mn_risk,
                "risk_score": mn_score,
                "complaint_count": mn_complaints,
                "evidence": [e.strip() for e in mn_evidence.splitlines() if e.strip()],
                "analyst_id": analyst_id or None,
                "input_type": "manual",
            })
            st.success("✅ 录入成功，刷新页面查看")


# ═══════════════════════════════════════════════════════════════
# Tab 4：反诈预警
# ═══════════════════════════════════════════════════════════════
with tab_aware:
    from backend.modules.fraud_database import get_stats as _get_stats

    stats = _get_stats()
    total = stats["total"]
    total_complaints = stats["total_complaints"]
    type_dist = stats["type_distribution"]

    # KPI 行
    kpi_cols = st.columns(4)
    kpi_data = [
        ("收录高危案例", total, "起", "#f44336"),
        ("累计投诉记录", total_complaints, "条", "#ff9800"),
        ("本月新增", 3, "起", "#ffeb3b"),
        ("预警覆盖高校", "24+", "所", "#4caf50"),
    ]
    for col, (label, value, unit, color) in zip(kpi_cols, kpi_data):
        with col:
            st.markdown(f"""<div class="stat-card">
              <div class="stat-num" style="color:{color}">{value}<span style="font-size:14px;font-weight:400">{unit}</span></div>
              <div style="color:#546e7a;font-size:12px;margin-top:6px">{label}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("---")

    col_chart, col_warn = st.columns([3, 2])

    with col_chart:
        st.markdown("### 📊 2026年招聘诈骗类型分布")
        palette = ["#f44336","#ff9800","#ffeb3b","#4caf50","#2196f3","#9c27b0"]
        total_cases = sum(v for _, v in type_dist) or 1
        for i, (ft, count) in enumerate(type_dist):
            pct = count / total_cases * 100
            color = palette[i % len(palette)]
            st.markdown(f"""<div style="margin-bottom:14px">
              <div style="display:flex;justify-content:space-between;margin-bottom:5px">
                <span style="color:#b0bec5;font-size:13px">{ft}</span>
                <span style="color:{color};font-size:12px;font-weight:700;font-family:'Share Tech Mono',monospace">{pct:.0f}% · {count}起</span>
              </div>
              <div style="background:#1e2d3d;border-radius:3px;height:8px">
                <div style="background:{color};height:8px;border-radius:3px;width:{pct}%;transition:width 1s"></div>
              </div>
            </div>""", unsafe_allow_html=True)

        # 风险分布
        st.markdown("### 🎯 风险等级分布")
        risk_dist = stats["risk_distribution"]
        risk_palette = {"极高":"#f44336","高":"#ff9800","中":"#ffeb3b","低":"#4caf50"}
        total_r = sum(risk_dist.values()) or 1
        rcols = st.columns(4)
        for col, (level, cnt) in zip(rcols, risk_dist.items()):
            pct_r = cnt / total_r * 100
            color_r = risk_palette.get(level, "#78909c")
            with col:
                st.markdown(f"""<div class="stat-card">
                  <div style="font-size:20px;font-weight:700;color:{color_r};font-family:'Share Tech Mono',monospace">{cnt}</div>
                  <div style="font-size:11px;color:#546e7a;margin-top:4px">{level}风险</div>
                  <div style="font-size:10px;color:#37474f">{pct_r:.0f}%</div>
                </div>""", unsafe_allow_html=True)

    with col_warn:
        st.markdown("### ⚠️ 实时预警信息")
        warnings = [
            ("⚠️", "高薪陷阱高发期", "三月应届生求职季，"月薪2万无经验"类帖子增加340%，请高度警惕。", "#ffeb3b"),
            ("🔍", "内推骗局新变种", "近期出现冒充大厂HR使用企业微信行骗，注意核验对方工牌和邮箱域名。", "#ff9800"),
            ("💳", "零成本≠零风险", "部分诈骗初期不收费，以"试用期任务"诱导垫资，警惕所有垫资兼职。", "#f97316"),
            ("🎓", "校招季风险提示", "虚假校招信息已出现，通过官方就业平台和辅导员核实任何校招信息。", "#4fc3f7"),
            ("📱", "维权渠道提示", "遭遇招聘诈骗可拨打 12321 举报热线，或通过求职平台内举报功能。", "#4caf50"),
        ]
        for icon, title, desc, color in warnings:
            st.markdown(f"""<div style="background:#0a1628;border:1px solid {color}33;border-left:3px solid {color};border-radius:6px;padding:12px 14px;margin-bottom:10px;">
              <div style="font-size:14px;font-weight:700;color:{color};margin-bottom:4px">{icon} {title}</div>
              <div style="font-size:12px;color:#78909c;line-height:1.6">{desc}</div>
            </div>""", unsafe_allow_html=True)

        # 最新录入
        st.markdown("### 📋 最新录入案例")
        recent = get_all_records()[:4]
        for rec in recent:
            risk = rec.get("risk_level","中")
            color_r = {"极高":"#f44336","高":"#ff9800","中":"#ffeb3b","低":"#4caf50"}.get(risk,"#78909c")
            company = rec.get("company") or "未知"
            ft = rec.get("fraud_type") or "待分类"
            st.markdown(f"""<div style="display:flex;justify-content:space-between;align-items:center;padding:7px 10px;background:#0d1b2a;border-radius:5px;margin:3px 0;font-size:12px">
              <span style="color:#b0bec5">{company[:12]}</span>
              <span style="color:#546e7a">{ft[:8]}</span>
              <span style="color:{color_r};font-weight:700">{risk}</span>
            </div>""", unsafe_allow_html=True)