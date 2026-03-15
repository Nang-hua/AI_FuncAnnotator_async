# -*- coding: utf-8 -*-
"""
AI_FuncAnnotator - IDA Pro plugin for AI-assisted function naming and commenting.

Async/UI-safe variant:
- Network requests run in a background worker thread.
- IDA extraction / rename / comment operations are marshaled back to the UI thread.
- Batch jobs are queued and processed serially so IDA stays responsive.
"""

import os
import re
import json
import queue
import threading
import traceback
import urllib.request
import urllib.error

import idaapi
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_ida
import ida_name
import ida_kernwin as kw
import ida_lines
import idautils
import idc


PLUGIN_NAME = "AI_FuncAnnotator"
PLUGIN_HOTKEY = "Ctrl-Alt-A"
CONFIG_FILENAME = "ai_func_annotator_config.json"
DEFAULT_MAX_FUNCTIONS = 5
DEFAULT_MAX_CALLS_PER_FUNCTION = 12
DEFAULT_COMMENT_LIMIT = 200
DEFAULT_MAX_INSN_PER_FUNCTION = 120
DEFAULT_MAX_PSEUDOCODE_LINES = 80
DEFAULT_TIMEOUT = 90

PROMPT_TEMPLATE = """你是经验丰富的逆向工程师。请分析给定的函数与其被调用子函数上下文，并严格返回 JSON。

任务：
1. 判断根函数最合理的功能名。
2. 给根函数生成不超过 {comment_limit} 个中文字符的功能注释。
3. 如果信息不足，可以请求继续查看根函数调用到的其他函数，但本轮总共最多只能查看 {max_functions} 个函数（含根函数）。
4. 优先结合伪代码、汇编、字符串、立即数、调用关系判断。

命名要求：
- function_name 必须是合法的 C/IDA 风格标识符，仅包含字母、数字、下划线，且不能以数字开头。
- 名称应简洁、可读、语义明确，例如 parse_config / decrypt_buffer / build_http_header。
- 不确定时给偏保守的名字，不要幻想具体算法。

注释要求：
- comment 为中文，不超过 {comment_limit} 字。
- comment 只描述功能，不写推理过程。

输出 JSON 格式：
{{
  "function_name": "...",
  "comment": "...",
  "confidence": 0.0,
  "need_more_context": false,
  "reason": "...",
  "requested_callees": ["sub_xxx", "0x401000"]
}}

规则：
- 只能输出 JSON，不要输出 markdown，不要输出解释。
- 若已足够判断，则 need_more_context=false，requested_callees=[]。
- 若需要更多上下文，只能从已提供的 root function 可调用目标里挑选 requested_callees。
- requested_callees 最多 4 个。
- 如果仍不确定，也必须给出当前最优命名和注释。
"""


if not hasattr(idaapi, "get_inf_structure"):
    class _InfProxy:
        @property
        def procname(self):
            return ida_ida.inf_get_procname()

        def is_be(self):
            return ida_ida.inf_is_be()

        def is_64bit(self):
            return ida_ida.inf_is_64bit()

        def is_32bit(self):
            return ida_ida.inf_is_32bit_exactly()

    def get_inf_structure():
        return _InfProxy()

    idaapi.get_inf_structure = get_inf_structure


def _plugin_dir():
    return os.path.dirname(os.path.abspath(__file__))


def _default_config_path():
    return os.path.join(_plugin_dir(), CONFIG_FILENAME)


def _ensure_default_config():
    path = _default_config_path()
    if os.path.exists(path):
        return path
    data = {
        "endpoint": "https://api.openai.com/v1/chat/completions",
        "api_key": "",
        "model": "gpt-4.1-mini",
        "timeout": DEFAULT_TIMEOUT,
        "max_functions": DEFAULT_MAX_FUNCTIONS,
        "max_calls_per_function": DEFAULT_MAX_CALLS_PER_FUNCTION,
        "max_insn_per_function": DEFAULT_MAX_INSN_PER_FUNCTION,
        "max_pseudocode_lines": DEFAULT_MAX_PSEUDOCODE_LINES,
        "comment_limit": DEFAULT_COMMENT_LIMIT,
        "system_prompt": "你是严谨的逆向工程师，擅长根据伪代码、汇编和调用关系给函数命名并写中文功能注释。",
        "rename_even_if_user_named": False,
        "verify_tls": True,
        "extra_headers": {}
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return path


def _load_json_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _clean_text(s):
    if s is None:
        return ""
    if isinstance(s, bytes):
        try:
            s = s.decode("utf-8", errors="ignore")
        except Exception:
            s = repr(s)
    s = str(s)
    s = s.replace("\r", "")
    return s.strip()


def _sanitize_identifier(name):
    name = _clean_text(name)
    name = re.sub(r"\s+", "_", name)
    name = re.sub(r"[^0-9A-Za-z_]", "_", name)
    name = re.sub(r"_+", "_", name).strip("_")
    if not name:
        return ""
    if re.match(r"^[0-9]", name):
        name = "fn_" + name
    return name[:128]


def _is_default_function_name(name):
    if not name:
        return True
    return bool(re.match(r"^(sub|nullsub|j_|unknown|loc)_[0-9A-Fa-f]+$", name))


def _short_string_literal(raw):
    s = _clean_text(raw)
    s = re.sub(r"\s+", " ", s)
    if len(s) > 120:
        s = s[:117] + "..."
    return s


def _sha1_text(s):
    if isinstance(s, str):
        s = s.encode("utf-8", errors="ignore")
    return __import__("hashlib").sha1(s).hexdigest()


class FunctionContextExtractor:
    def __init__(self, cfg):
        self.cfg = cfg

    def arch_string(self):
        inf = idaapi.get_inf_structure()
        proc = getattr(inf, "procname", "unknown") or "unknown"
        bits = "64" if inf.is_64bit() else ("32" if inf.is_32bit() else "16")
        endian = "be" if inf.is_be() else "le"
        return "%s-%s-%s" % (proc, bits, endian)

    def _decompile(self, ea):
        if not ida_hexrays.init_hexrays_plugin():
            return ""
        try:
            cfunc = ida_hexrays.decompile(ea)
            if not cfunc:
                return ""
            lines = []
            sv = cfunc.get_pseudocode()
            limit = int(self.cfg.get("max_pseudocode_lines", DEFAULT_MAX_PSEUDOCODE_LINES))
            for i, line in enumerate(sv):
                if i >= limit:
                    break
                text = ida_lines.tag_remove(line.line)
                text = _clean_text(text)
                if text:
                    lines.append(text)
            return "\n".join(lines)
        except Exception:
            return ""

    def _strings_for_insn(self, ea):
        result = []
        seen = set()
        for ref in idautils.DataRefsFrom(ea):
            for strtype in (idc.STRTYPE_C, idc.STRTYPE_C_16):
                try:
                    raw = idc.get_strlit_contents(ref, -1, strtype)
                    if raw:
                        s = _short_string_literal(raw)
                        if s and s not in seen:
                            seen.add(s)
                            result.append(s)
                            break
                except Exception:
                    pass
        return result

    def _collect_disasm(self, pfn):
        lines = []
        callees = []
        strings = []
        immediates = []
        seen_callees = set()
        seen_strings = set()
        max_insn = int(self.cfg.get("max_insn_per_function", DEFAULT_MAX_INSN_PER_FUNCTION))
        max_calls = int(self.cfg.get("max_calls_per_function", DEFAULT_MAX_CALLS_PER_FUNCTION))
        count = 0

        for ea in idautils.FuncItems(pfn.start_ea):
            if not idc.is_code(idc.get_full_flags(ea)):
                continue
            line = idc.generate_disasm_line(ea, 0) or ""
            line = ida_lines.tag_remove(line)
            line = _clean_text(line)
            if line:
                lines.append("0x%X: %s" % (ea, line))
                count += 1
                if count >= max_insn:
                    break

            mnem = (idc.print_insn_mnem(ea) or "").lower()
            if mnem == "call":
                target = idc.get_operand_value(ea, 0)
                if target != idaapi.BADADDR:
                    callee = idaapi.get_func(target)
                    if callee:
                        name = ida_name.get_name(callee.start_ea) or ("sub_%X" % callee.start_ea)
                        key = callee.start_ea
                        if key not in seen_callees and len(callees) < max_calls:
                            seen_callees.add(key)
                            callees.append({"ea": "0x%X" % callee.start_ea, "name": name})
            for idx in range(2):
                if idc.get_operand_type(ea, idx) == idc.o_imm:
                    try:
                        immediates.append(int(idc.get_operand_value(ea, idx)) & 0xFFFFFFFFFFFFFFFF)
                    except Exception:
                        pass
            for s in self._strings_for_insn(ea):
                if s not in seen_strings:
                    seen_strings.add(s)
                    strings.append(s)

        return {
            "disasm": "\n".join(lines),
            "callees": callees,
            "strings": strings[:24],
            "immediates": sorted(set(immediates))[:24],
        }

    def extract_function(self, ea):
        pfn = idaapi.get_func(ea)
        if not pfn:
            return None
        name = ida_name.get_name(pfn.start_ea) or ("sub_%X" % pfn.start_ea)
        meta = self._collect_disasm(pfn)
        pseudocode = self._decompile(pfn.start_ea)
        return {
            "ea": "0x%X" % pfn.start_ea,
            "name": name,
            "arch": self.arch_string(),
            "size": int(max(0, pfn.end_ea - pfn.start_ea)),
            "pseudocode": pseudocode,
            "disasm": meta["disasm"],
            "strings": meta["strings"],
            "immediates": meta["immediates"],
            "callees": meta["callees"],
            "fingerprint": _sha1_text((meta["disasm"] or "") + "\n" + (pseudocode or "")),
        }


class AIClient:
    def __init__(self, cfg):
        self.cfg = cfg

    def _headers(self):
        headers = {"Content-Type": "application/json"}
        api_key = _clean_text(self.cfg.get("api_key", ""))
        if api_key:
            headers["Authorization"] = "Bearer %s" % api_key
        extra = self.cfg.get("extra_headers", {}) or {}
        if isinstance(extra, dict):
            for k, v in extra.items():
                headers[str(k)] = str(v)
        return headers

    def chat(self, messages):
        endpoint = _clean_text(self.cfg.get("endpoint", ""))
        if not endpoint:
            raise RuntimeError("Config missing endpoint")
        payload = {
            "model": self.cfg.get("model", "gpt-4.1-mini"),
            "temperature": 0.1,
            "messages": messages,
            "response_format": {"type": "json_object"},
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(endpoint, data=data, headers=self._headers(), method="POST")
        timeout = int(self.cfg.get("timeout", DEFAULT_TIMEOUT))
        context = None
        if not bool(self.cfg.get("verify_tls", True)):
            import ssl
            context = ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
                raw = resp.read().decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="ignore") if hasattr(e, "read") else str(e)
            raise RuntimeError("HTTP %s: %s" % (getattr(e, "code", "?"), raw))
        except Exception as e:
            raise RuntimeError("Request failed: %s" % e)

        try:
            obj = json.loads(raw)
            content = obj["choices"][0]["message"]["content"]
        except Exception:
            raise RuntimeError("Unexpected API response: %s" % raw[:1000])

        try:
            return json.loads(content)
        except Exception:
            m = re.search(r"\{.*\}", content, re.S)
            if m:
                return json.loads(m.group(0))
            raise RuntimeError("Model did not return valid JSON: %s" % content[:1000])


class AnalysisManager:
    def __init__(self, cfg):
        self.cfg = cfg
        self.extractor = FunctionContextExtractor(cfg)
        self.client = AIClient(cfg)

    def _choose_requested(self, root_ctx, requested_names, expanded_eas):
        chosen = []
        lookup = {}
        for c in root_ctx.get("callees", []):
            lookup[c.get("name")] = c
            lookup[c.get("ea")] = c
        for item in requested_names or []:
            key = _clean_text(item)
            callee = lookup.get(key)
            if not callee:
                for k, v in lookup.items():
                    if key and key.lower() in _clean_text(k).lower():
                        callee = v
                        break
            if not callee:
                continue
            try:
                ea = int(str(callee.get("ea", "0")).replace("0x", ""), 16)
            except Exception:
                continue
            if ea in expanded_eas:
                continue
            chosen.append(ea)
            if len(chosen) >= 4:
                break
        return chosen

    def _build_user_content(self, root_ctx, contexts, round_idx):
        body = {
            "round": round_idx,
            "root_function": root_ctx,
            "available_total_limit": int(self.cfg.get("max_functions", DEFAULT_MAX_FUNCTIONS)),
            "current_context_count": len(contexts),
            "contexts": contexts,
        }
        return json.dumps(body, ensure_ascii=False, indent=2)

    def analyze_root(self, root_ea, extract_cb):
        max_functions = max(1, min(5, int(self.cfg.get("max_functions", DEFAULT_MAX_FUNCTIONS))))
        root_ctx = extract_cb(root_ea)
        if not root_ctx:
            raise RuntimeError("Current address is not inside a function")

        contexts = [root_ctx]
        expanded_eas = {int(root_ctx["ea"], 16)}
        system_prompt = _clean_text(self.cfg.get("system_prompt", "")) or "你是严谨的逆向工程师。"
        prompt = PROMPT_TEMPLATE.format(
            comment_limit=int(self.cfg.get("comment_limit", DEFAULT_COMMENT_LIMIT)),
            max_functions=max_functions,
        )

        final_result = None
        rounds = 0
        while rounds < max_functions:
            rounds += 1
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt + "\n\n上下文：\n" + self._build_user_content(root_ctx, contexts, rounds)},
            ]
            result = self.client.chat(messages)
            final_result = result
            if not bool(result.get("need_more_context", False)):
                break
            if len(contexts) >= max_functions:
                break
            requested = self._choose_requested(root_ctx, result.get("requested_callees", []), expanded_eas)
            if not requested:
                break
            for ea in requested:
                if len(contexts) >= max_functions:
                    break
                ctx = extract_cb(ea)
                if ctx:
                    contexts.append(ctx)
                    expanded_eas.add(ea)
            if len(contexts) >= max_functions:
                break

        return {"root": root_ctx, "contexts": contexts, "ai": final_result or {}}


class IDAApply:
    def __init__(self, cfg):
        self.cfg = cfg

    def apply(self, root_ea, result):
        ai = result.get("ai", {}) or {}
        orig_name = ida_name.get_name(root_ea) or ("sub_%X" % root_ea)
        suggested = _sanitize_identifier(ai.get("function_name", ""))
        comment = _clean_text(ai.get("comment", ""))
        limit = int(self.cfg.get("comment_limit", DEFAULT_COMMENT_LIMIT))
        if len(comment) > limit:
            comment = comment[:limit]
        confidence = ai.get("confidence", 0.0)
        reason = _clean_text(ai.get("reason", ""))

        rename_done = False
        final_name = orig_name
        if suggested:
            rename_even_if_user_named = bool(self.cfg.get("rename_even_if_user_named", False))
            if rename_even_if_user_named or _is_default_function_name(orig_name):
                flags = ida_name.SN_NOWARN | ida_name.SN_NOCHECK
                if ida_name.set_name(root_ea, suggested, flags):
                    final_name = suggested
                    rename_done = True

        cmt_lines = []
        if comment:
            cmt_lines.append(comment)
        cmt_lines.append("[AI] confidence=%.2f" % (float(confidence) if confidence is not None else 0.0))
        if reason:
            cmt_lines.append("[AI] %s" % reason[:200])
        if suggested and not rename_done and suggested != orig_name:
            cmt_lines.append("[AI] suggested_name=%s" % suggested)
        pfn = idaapi.get_func(root_ea)
        if pfn:
            ida_funcs.set_func_cmt(pfn, "\n".join(cmt_lines), True)
        return {
            "original_name": orig_name,
            "final_name": final_name,
            "rename_done": rename_done,
            "comment": comment,
        }


class ActionHandler(idaapi.action_handler_t):
    def __init__(self, callback):
        super(ActionHandler, self).__init__()
        self.callback = callback

    def activate(self, ctx):
        try:
            self.callback(ctx)
        except Exception:
            print(traceback.format_exc())
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class UIFacade:
    MENU_PREFIX = "Edit/Plugins/"

    def __init__(self):
        _ensure_default_config()
        self.cfg = self.load_cfg()
        self.manager = AnalysisManager(self.cfg)
        self.applier = IDAApply(self.cfg)
        self.task_queue = queue.Queue()
        self._stop_evt = threading.Event()
        self._worker = threading.Thread(target=self._worker_loop, name="AI_FuncAnnotatorWorker", daemon=True)
        self._worker.start()

    def load_cfg(self):
        path = _ensure_default_config()
        cfg = _load_json_file(path)
        cfg["max_functions"] = max(1, min(5, int(cfg.get("max_functions", DEFAULT_MAX_FUNCTIONS))))
        return cfg

    def reload_cfg(self):
        self.cfg = self.load_cfg()
        self.manager = AnalysisManager(self.cfg)
        self.applier = IDAApply(self.cfg)

    def _run_in_main_thread(self, fn, write=True):
        holder = {"ok": False, "result": None, "error": None}
        flags = kw.MFF_WRITE if write else kw.MFF_FAST

        def wrapper():
            try:
                holder["result"] = fn()
                holder["ok"] = True
            except Exception as e:
                holder["error"] = e
            return 1

        kw.execute_sync(wrapper, flags)
        if holder["error"] is not None:
            raise holder["error"]
        return holder["result"]

    def _msg(self, text):
        def cb():
            kw.msg(text)
        self._run_in_main_thread(cb, write=False)

    def _warn(self, text):
        def cb():
            kw.warning(text)
        self._run_in_main_thread(cb, write=True)

    def _extract_in_main(self, ea):
        return self._run_in_main_thread(lambda: self.manager.extractor.extract_function(ea), write=False)

    def _apply_in_main(self, ea, result):
        return self._run_in_main_thread(lambda: self.applier.apply(ea, result), write=True)

    def _normalize_function_ea(self, ea):
        pfn = idaapi.get_func(ea)
        return pfn.start_ea if pfn else None

    def _enqueue_tasks(self, eas, label):
        tasks = []
        seen = set()
        for ea in eas:
            fea = self._normalize_function_ea(ea)
            if fea is None or fea in seen:
                continue
            seen.add(fea)
            tasks.append(fea)
        if not tasks:
            self._warn("No valid function to analyze")
            return
        for ea in tasks:
            self.task_queue.put(ea)
        self._msg("[%s] queued %d task(s) from %s\n" % (PLUGIN_NAME, len(tasks), label))

    def _worker_loop(self):
        while not self._stop_evt.is_set():
            try:
                ea = self.task_queue.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                self.reload_cfg()
                self._msg("[%s] analyzing 0x%X ...\n" % (PLUGIN_NAME, ea))
                result = self.manager.analyze_root(ea, self._extract_in_main)
                applied = self._apply_in_main(ea, result)
                ai = result.get("ai", {}) or {}
                self._msg("[%s] analyzed 0x%X -> %s (renamed=%s, confidence=%s, contexts=%d)\n" % (
                    PLUGIN_NAME,
                    ea,
                    applied.get("final_name"),
                    applied.get("rename_done"),
                    ai.get("confidence", 0.0),
                    len(result.get("contexts", [])),
                ))
                if applied.get("comment"):
                    self._msg("[%s] comment: %s\n" % (PLUGIN_NAME, applied.get("comment")))
            except Exception as e:
                msg = "[%s] error on 0x%X: %s\n%s\n" % (PLUGIN_NAME, ea, e, traceback.format_exc())
                self._msg(msg)
            finally:
                self.task_queue.task_done()

    def analyze_current(self, ctx):
        ea = kw.get_screen_ea()
        pfn = idaapi.get_func(ea)
        if not pfn:
            self._warn("Current address is not inside a function")
            return
        self._enqueue_tasks([pfn.start_ea], "current function")

    def analyze_selected(self, ctx):
        ok, start_ea, end_ea = kw.read_range_selection(None)
        if not ok:
            self._warn("Please select a range in the disassembly view first")
            return
        seen = list(idautils.Functions(start_ea, end_ea))
        if not seen:
            pfn = idaapi.get_func(start_ea)
            if pfn:
                seen = [pfn.start_ea]
        if not seen:
            self._warn("No function found in selected range")
            return
        self._enqueue_tasks(seen, "selected range")

    def show_config(self, ctx):
        path = _ensure_default_config()
        kw.info("Config path:\n%s" % path)

    def register_actions(self):
        actions = [
            ("ai_func_annotator:analyze_current", "AI analyze current function", self.analyze_current, PLUGIN_HOTKEY),
            ("ai_func_annotator:analyze_selected", "AI analyze selected functions", self.analyze_selected, ""),
            ("ai_func_annotator:show_config", "Show AI plugin config path", self.show_config, ""),
        ]
        for action_id, text, cb, hotkey in actions:
            desc = idaapi.action_desc_t(action_id, text, ActionHandler(cb), hotkey, text, 199)
            idaapi.register_action(desc)
            idaapi.attach_action_to_menu(self.MENU_PREFIX, action_id, idaapi.SETMENU_APP)

    def shutdown(self):
        self._stop_evt.set()


class PopupHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        wtype = idaapi.get_widget_type(widget)
        if wtype == kw.BWN_DISASM or wtype == kw.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(widget, popup, "ai_func_annotator:analyze_current", "AI Func/")
            idaapi.attach_action_to_popup(widget, popup, "ai_func_annotator:analyze_selected", "AI Func/")
            idaapi.attach_action_to_popup(widget, popup, "ai_func_annotator:show_config", "AI Func/")


class AI_FuncAnnotatorPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "AI-assisted function naming and comments"
    help = "Analyze functions with AI API, add function comments, rename functions, recursively inspect callees up to 5 contexts"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        try:
            self.ui = UIFacade()
            self.ui.register_actions()
            self.hooks = PopupHooks()
            self.hooks.hook()
            kw.msg("[%s] loaded. Config: %s\n" % (PLUGIN_NAME, _ensure_default_config()))
            return idaapi.PLUGIN_KEEP
        except Exception:
            print(traceback.format_exc())
            return idaapi.PLUGIN_SKIP

    def run(self, arg):
        self.ui.analyze_current(None)

    def term(self):
        try:
            if hasattr(self, "ui") and self.ui:
                self.ui.shutdown()
        except Exception:
            pass


def PLUGIN_ENTRY():
    return AI_FuncAnnotatorPlugin()
