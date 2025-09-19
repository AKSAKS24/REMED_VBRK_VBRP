from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import re

app = FastAPI()


class Payload(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    class_implementation: Optional[str] = ""
    code: str


class ResponseModel(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    class_implementation: Optional[str] = ""
    original_code: str
    remediated_code: str


def select_table_aliases(select_stmt: str):
    """
    Extract only VBRK/VBRP tables and their aliases safely.
    Handles FROM and JOIN (with/without AS).
    """
    aliases = []
    reserved = {"into", "where", "order", "group", "having", "for", "as"}

    # FROM clause
    m_from = re.search(
        r'\bfrom\s+(vbrk|vbrp)(?:\s+(?:as\s+)?([a-zA-Z_]\w+))?',
        select_stmt,
        re.IGNORECASE,
    )
    if m_from:
        tbl = m_from.group(1).upper()
        als = m_from.group(2)
        if als and als.lower() not in reserved:
            aliases.append((tbl, als))
        else:
            aliases.append((tbl, tbl))

    # JOIN clauses
    join_re = re.compile(
        r'\b(?:inner|left|right|full|cross|outer|left\s+outer|right\s+outer)?\s*join\s+(vbrk|vbrp)(?:\s+(?:as\s+)?([a-zA-Z_]\w+))?',
        flags=re.IGNORECASE,
    )
    for m in join_re.finditer(select_stmt):
        tbl = m.group(1).upper()
        als = m.group(2)
        if als and als.lower() not in reserved:
            aliases.append((tbl, als))
        else:
            aliases.append((tbl, tbl))

    return aliases


def process_abap_code(payload: Payload):
    code = payload.code
    original_code = code
    today_str = datetime.now().strftime("%Y-%m-%d")
    tag = f'"Added By Pwc {today_str}'
    remediated_code = code

    select_pattern = re.compile(
        r"""(
            select
            (?:\s+single)?        # select single
            [\s\S]+?              # fields
            \bfrom\b
            [\s\S]+?
            (?:into[\s\S]+?)?     # INTO part
            (?:where[\s\S]+?)?    # WHERE part
            (?:for\s+all\s+entries[\s\S]+?)?
            (?:group\s+by[\s\S]+?)?
            (?:having[\s\S]+?)?
            \.
        )""",
        re.IGNORECASE | re.VERBOSE | re.DOTALL,
    )

    matches = list(select_pattern.finditer(code))
    for m in reversed(matches):
        select_stmt = m.group(0)
        tables_and_aliases = select_table_aliases(select_stmt)

        if not tables_and_aliases:
            continue

        # Build draft conditions
        draft_conds = []
        for tbl, alias in tables_and_aliases:
            cond = f"{alias}~draft = space" if alias else f"{tbl.lower()}~draft = space"
            # skip if already present
            if re.search(re.escape(cond), select_stmt, re.IGNORECASE):
                continue
            draft_conds.append(f"{cond} {tag}")

        if not draft_conds:
            continue

        draft_cond = " AND ".join(draft_conds)

        has_where = bool(re.search(r'\bwhere\b', select_stmt, re.IGNORECASE))
        select_stmt_mod = select_stmt

        if has_where:
            # Append to WHERE condition
            select_stmt_mod = re.sub(
                r'(where\s+)',
                rf'\1{draft_cond} AND ',
                select_stmt_mod,
                flags=re.IGNORECASE,
                count=1,
            )
        else:
            # Ensure WHERE comes *after* INTO
            select_stmt_mod = re.sub(
                r'(into[\s\S]+?)(\.)',
                rf'\1 where {draft_cond}\2',
                select_stmt_mod,
                flags=re.IGNORECASE,
                count=1,
            )

        remediated_code = (
            remediated_code[: m.start()]
            + select_stmt_mod
            + remediated_code[m.end():]
        )

    return ResponseModel(
        pgm_name=payload.pgm_name,
        inc_name=payload.inc_name,
        type=payload.type,
        name=payload.name,
        class_implementation=payload.class_implementation,
        original_code=original_code,
        remediated_code=remediated_code,
    )


@app.post('/remediate_abap', response_model=ResponseModel)
async def remediate_abap(payload: Payload):
    return process_abap_code(payload)
