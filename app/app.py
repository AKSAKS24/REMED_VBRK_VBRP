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
    match = re.search(r'select\s+(?:single\s+)?(.*?)\s+from', select_stmt, re.IGNORECASE | re.DOTALL)
    if not match:
        return []
    fields = match.group(1).strip()
    if fields == '*' or fields.lower() == 'distinct *':
        return []
    # Remove distinct if present
    fields = re.sub(r'\bdistinct\s+', '', fields, flags=re.IGNORECASE)
    # Normalize whitespace
    fields = " ".join(fields.split())
    # Split by comma (if user used commas) and strip
    fields_list = [f.strip() for f in fields.split(',') if f.strip()]
    # If user wrote space-separated fields (rare), keep them as-is
    if len(fields_list) == 1 and ' ' in fields_list[0]:
        return [f.strip() for f in fields_list[0].split() if f.strip()]
    return fields_list

def select_table_aliases(select_stmt: str):
    """
    Returns a list of tuples (table, alias) ONLY for VBRK/VBRP,
    regardless of whether they are in FROM or any kind of JOIN,
    and whether alias is declared with `AS` or simply as `vbrk vbrk`.
    """
    aliases = []

    # FROM: allow optional alias with or without AS
    m_from = re.search(r'\bfrom\s+(vbrk|vbrp)(?:\s+(?:as\s+)?(\w+))?', select_stmt, re.IGNORECASE)
    if m_from:
        tbl, als = m_from.group(1).upper(), m_from.group(2)
        aliases.append((tbl, als if als else tbl))

    # JOINs: match INNER/LEFT/RIGHT/FULL/CROSS/OUTER and alias with/without AS
    join_re = re.compile(
        r'\b(?:inner|left|right|full|cross|outer|left\s+outer|right\s+outer)?\s*join\s+(vbrk|vbrp)(?:\s+(?:as\s+)?(\w+))?',
        flags=re.IGNORECASE
    )
    for m in join_re.finditer(select_stmt):
        tbl, als = m.group(1).upper(), m.group(2)
        aliases.append((tbl, als if als else tbl))

    return aliases

def process_abap_code(payload: Payload):
    code = payload.code
    original_code = code
    today_str = datetime.now().strftime("%Y-%m-%d")
    tag = f'"Added By Pwc {today_str}"'
    remediated_code = code

    # Select pattern: use DOTALL so '.' matches newlines and the whole select is captured
    select_pattern = re.compile(
        r"""(
            select
            (?:\s+single)?
            [\s\S]+?                    # fields (now matches across lines)
            \bfrom\b
            [\s\S]+?                    # tables / joins
            (?:\bwhere\b[\s\S]+?)?      # optional where
            (?:for\s+all\s+entries[\s\S]+?)?
            (?:order\s+by[\s\S]+?)?
            (?:group\s+by[\s\S]+?)?
            (?:having[\s\S]+?)?
            into[\s\S]+?                # stop at into (so we don't swallow subqueries)
            \.                          # ending period
        )""",
        re.IGNORECASE | re.VERBOSE | re.DOTALL
    )

    matches = list(select_pattern.finditer(code))
    for m in reversed(matches):
        select_stmt = m.group(0)

        # only care about VBRK/VBRP aliases
        tables_and_aliases = select_table_aliases(select_stmt)
        if not tables_and_aliases:
            continue

        # build draft conditions only for vbrk/vbrp aliases
        draft_conds = [f"{alias}~draft = space {tag}" for tbl, alias in tables_and_aliases]
        draft_cond = " AND ".join(draft_conds)

        has_where = bool(re.search(r'\bwhere\b', select_stmt, re.IGNORECASE))
        for_all_entries = bool(re.search(r'for\s+all\s+entries', select_stmt, re.IGNORECASE))

        select_stmt_mod = select_stmt

        # If a WHERE exists — inject our draft cond right after the first WHERE
        if has_where:
            select_stmt_mod = re.sub(r'(where\s+)', rf'\1{draft_cond} and ', select_stmt_mod, flags=re.IGNORECASE, count=1)
        else:
            # find earliest insertion point: prefer before INTO (so SELECT ... WHERE ... ORDER BY ... INTO)
            lower = select_stmt_mod.lower()
            candidates = []
            for kw in [' into ', ' order by ', ' group by ', ' having ']:
                pos = lower.find(kw)
                if pos != -1:
                    candidates.append(pos)
            if candidates:
                insert_pos = min(candidates)
            else:
                # fallback: before final period
                insert_pos = len(select_stmt_mod) - 1
            select_stmt_mod = select_stmt_mod[:insert_pos] + f' where {draft_cond} ' + select_stmt_mod[insert_pos:]

        # ORDER BY insertion: use space-separated fields (ABAP expects fields separated by spaces)
        field_list = extract_field_list(select_stmt)
        # fields for ORDER BY should be space-separated (remove commas)
        order_fields = " ".join([f for f in field_list]) if field_list else ""
        has_order = bool(re.search(r'\border\s+by\b', select_stmt_mod, re.IGNORECASE))

        if not for_all_entries and field_list and not has_order:
            # place ORDER BY before INTO (so SELECT ... WHERE ... ORDER BY ... INTO ...)
            m_into = re.search(r'\binto\b', select_stmt_mod, re.IGNORECASE)
            if m_into:
                pos_into = m_into.start()
                select_stmt_mod = select_stmt_mod[:pos_into] + f' order by {order_fields} {tag} ' + select_stmt_mod[pos_into:]
            else:
                # fallback: append before final period
                select_stmt_mod = select_stmt_mod.rstrip('. \n') + f' order by {order_fields} {tag}.'

        # replace in the code
        remediated_code = remediated_code[:m.start()] + select_stmt_mod + remediated_code[m.end():]

    return ResponseModel(
        pgm_name=payload.pgm_name,
        inc_name=payload.inc_name,
        type=payload.type,
        name=payload.name,
        class_implementation=payload.class_implementation,
        original_code=original_code,
        remediated_code=remediated_code
    )

@app.post('/remediate_abap', response_model=ResponseModel)
def remediate_abap(payload: Payload):
    return process_abap_code(payload)