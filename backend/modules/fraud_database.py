# backend/modules/fraud_database.py
"""
涉诈信息库 — 基于 JSON 文件的轻量级持久化存储
支持：录入、查询、统计、关联分析
Streamlit Cloud 部署友好（无需外部数据库）
"""
import json
import os
import uuid
from datetime import datetime
from typing import List, Optional, Dict
from loguru import logger

# 数据文件路径（项目根目录下的 data/ 目录）
_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_PATH = os.path.join(_BASE, "data", "fraud_db.json")

# 内置示例数据（首次启动时写入，用于演示）
_SEED_DATA = [
    {
        "id": "seed-001", "created_at": "2026-03-10T08:00:00",
        "company": "卓越人才发展有限公司", "url": None, "input_type": "company_name",
        "fraud_type": "付费培训诈骗", "risk_level": "极高", "risk_score": 91,
        "evidence": ["要求缴纳3800元培训费", "承诺100%推荐就业", "无正规营业执照"],
        "complaint_count": 47, "analyst_id": "P001", "report_id": "RPT-SEED001", "notes": "已移交网安",
    },
    {
        "id": "seed-002", "created_at": "2026-03-08T14:30:00",
        "company": "猎头精英咨询（深圳）", "url": None, "input_type": "chat_log",
        "fraud_type": "虚假内推诈骗", "risk_level": "高", "risk_score": 78,
        "evidence": ["声称有腾讯内部名额", "要求转账500元保证金", "联系方式为个人微信"],
        "complaint_count": 23, "analyst_id": "P002", "report_id": "RPT-SEED002", "notes": "",
    },
    {
        "id": "seed-003", "created_at": "2026-03-15T10:15:00",
        "company": "新远教育科技", "url": None, "input_type": "recruitment_text",
        "fraud_type": "刷单返佣诈骗", "risk_level": "极高", "risk_score": 95,
        "evidence": ["以'兼职'名义招募", "要求垫付购买电商商品", "前期小额返佣诱导"],
        "complaint_count": 89, "analyst_id": "P001", "report_id": "RPT-SEED003", "notes": "受害人已超80人",
    },
    {
        "id": "seed-004", "created_at": "2026-03-18T09:00:00",
        "company": "领航职业规划中心", "url": None, "input_type": "recruitment_text",
        "fraud_type": "押金保证金诈骗", "risk_level": "高", "risk_score": 72,
        "evidence": ["要求缴纳1200元诚信金", "称离职退还但实际不退", "营业执照注册仅2个月"],
        "complaint_count": 31, "analyst_id": "P003", "report_id": "RPT-SEED004", "notes": "",
    },
]


def _ensure_db():
    """确保数据库文件存在，首次创建时写入种子数据"""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    if not os.path.exists(DB_PATH):
        data = {
            "version": "1.0",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "records": _SEED_DATA,
        }
        with open(DB_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info(f"[DB] 数据库初始化完成，写入 {len(_SEED_DATA)} 条示例记录")


def load_db() -> Dict:
    _ensure_db()
    try:
        with open(DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"[DB] 读取失败: {e}")
        return {"records": _SEED_DATA}


def save_db(data: Dict):
    data["updated_at"] = datetime.utcnow().isoformat()
    try:
        with open(DB_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"[DB] 写入失败: {e}")


def add_record(record: Dict) -> str:
    """录入新涉诈记录，返回 ID"""
    db = load_db()
    record["id"] = str(uuid.uuid4())[:8]
    record["created_at"] = datetime.utcnow().isoformat()
    db["records"].insert(0, record)
    save_db(db)
    logger.info(f"[DB] 新增记录 #{record['id']}: {record.get('company', record.get('url', ''))}")
    return record["id"]


def search_records(query: str = "", fraud_type: str = "", risk_level: str = "") -> List[Dict]:
    """多条件查询"""
    records = load_db()["records"]
    if query:
        q = query.lower()
        records = [
            r for r in records
            if q in r.get("company", "").lower()
            or q in r.get("url", "").lower()
            or q in r.get("fraud_type", "").lower()
            or any(q in e.lower() for e in r.get("evidence", []))
        ]
    if fraud_type:
        records = [r for r in records if r.get("fraud_type") == fraud_type]
    if risk_level:
        records = [r for r in records if r.get("risk_level") == risk_level]
    return records


def get_all_records() -> List[Dict]:
    return load_db()["records"]


def get_stats() -> Dict:
    """统计信息，用于反诈预警模块"""
    records = load_db()["records"]
    type_counts: Dict[str, int] = {}
    risk_counts: Dict[str, int] = {"极高": 0, "高": 0, "中": 0, "低": 0}

    for r in records:
        ft = r.get("fraud_type") or "未分类"
        type_counts[ft] = type_counts.get(ft, 0) + 1
        rl = r.get("risk_level", "中")
        if rl in risk_counts:
            risk_counts[rl] += 1

    total_complaints = sum(r.get("complaint_count", 0) for r in records)
    return {
        "total": len(records),
        "total_complaints": total_complaints,
        "type_distribution": sorted(type_counts.items(), key=lambda x: x[1], reverse=True),
        "risk_distribution": risk_counts,
    }


def get_related_records(company: str = "", fraud_type: str = "") -> List[Dict]:
    """关联查询：同公司 or 同诈骗类型"""
    records = load_db()["records"]
    related = []
    for r in records:
        if company and company in r.get("company", ""):
            related.append(r)
        elif fraud_type and r.get("fraud_type") == fraud_type:
            related.append(r)
    return related