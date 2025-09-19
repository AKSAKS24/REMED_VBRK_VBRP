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


def extract_field_list(select_stmt: str):
    match = re.search(r'select\s+(?:single\s+)?(.*?)\s+from', select_stmt,
                      re.IGNORECASE | re.DOTALL)
    if not match:
        return []
    fields = match.group(1).strip()
    if fields == '*' or fields.lower() == 'distinct *':
        return []
    fields = re.sub(r'\bdistinct\s+', '', fields, flags=re.IGNORECASE)
    fields = " ".join(fields.split())
    fields_list = [f.strip() for f in fields.split(',') if f.strip()]
    if len(fields_list) == 1 and ' ' in fields_list[0]:
        return [f.strip() for f in fields_list[0].split() if f.strip()]
    return fields_list


def select_table_aliases(select_stmt: str):
    """
    Extract only VBRK/VBRP tables and their aliases safely.
    Handles FROM and JOIN (with/without AS).
    Avoids misreading INTO/WHERE/ORDER as alias.
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
            aliases.append((tbl, tbl))  # no alias → use table name

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
            (?:\s+single)?
            [\s\S]+?
            \bfrom\b
            [\s\S]+?
            (?:\bwhere\b[\s\S]+?)?
            (?:for\s+all\s+entries[\s\S]+?)?
            (?:order\s+by[\s\S]+?)?
            (?:group\s+by[\s\S]+?)?
            (?:having[\s\S]+?)?
            into[\s\S]+?
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

        # Build draft condition
        draft_conds = []
        for tbl, alias in tables_and_aliases:
            if tbl in ("VBRK", "VBRP"):
                if alias and alias.upper() != tbl:
                    draft_conds.append(f"{alias}~draft = space {tag}")
                else:
                    draft_conds.append(f"{tbl.lower()}~draft = space {tag}")

        if not draft_conds:
            continue

        draft_cond = " AND ".join(draft_conds)

        has_where = bool(re.search(r'\bwhere\b', select_stmt, re.IGNORECASE))
        for_all_entries = bool(
            re.search(r'for\s+all\s+entries', select_stmt, re.IGNORECASE)
        )
        select_stmt_mod = select_stmt

        if for_all_entries:
            # FOR ALL ENTRIES: inject after WHERE
            if has_where:
                select_stmt_mod = re.sub(
                    r'(where\s+)',
                    rf'\1{draft_cond} and ',
                    select_stmt_mod,
                    flags=re.IGNORECASE,
                    count=1,
                )
            else:
                # If no WHERE before FAE, inject it
                select_stmt_mod = re.sub(
                    r'(for\s+all\s+entries\s+in\s+\w+)',
                    rf'where {draft_cond} \1',
                    select_stmt_mod,
                    flags=re.IGNORECASE,
                    count=1,
                )
        else:
            if has_where:
                select_stmt_mod = re.sub(
                    r'(where\s+)',
                    rf'\1{draft_cond} and ',
                    select_stmt_mod,
                    flags=re.IGNORECASE,
                    count=1,
                )
            else:
                # Insert before INTO / ORDER BY / GROUP BY / HAVING
                lower = select_stmt_mod.lower()
                candidates = []
                for kw in [' into ', ' order by ', ' group by ', ' having ']:
                    pos = lower.find(kw)
                    if pos != -1:
                        candidates.append(pos)
                if candidates:
                    insert_pos = min(candidates)
                else:
                    insert_pos = len(select_stmt_mod) - 1
                select_stmt_mod = (
                    select_stmt_mod[:insert_pos]
                    + f' where {draft_cond} '
                    + select_stmt_mod[insert_pos:]
                )

        # ORDER BY fix
        field_list = extract_field_list(select_stmt)
        order_fields = " ".join(field_list) if field_list else ""
        has_order = bool(
            re.search(r'\border\s+by\b', select_stmt_mod, re.IGNORECASE)
        )

        if not for_all_entries and field_list and not has_order:
            m_into = re.search(r'\binto\b', select_stmt_mod, re.IGNORECASE)
            if m_into:
                pos_into = m_into.start()
                select_stmt_mod = (
                    select_stmt_mod[:pos_into]
                    + f' order by {order_fields} {tag} '
                    + select_stmt_mod[pos_into:]
                )
            else:
                select_stmt_mod = select_stmt_mod.rstrip('. \n') + \
                    f' order by {order_fields} {tag}.'

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
