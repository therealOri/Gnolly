"""
gnolly.relay
~~~~~~~~~~~~
Shared generation of lines, factored out of gnolly.selfhash, so any module
in the pipeline can hide a sensitive call behind the same family of
dunder-protocol disguises instead of each site inventing its own.

The caller always supplies the real call as a plain expression string
(e.g. "(fn)(src_var, globals())" or "getattr(h_sys, s_fn(x))(obn(1))")
-> this module has no idea what the call does and doesn't need;
it only decides how the call gets reached.

Three families, because callers need different guarantees:

one_shot_call_lines()
    Returns -> (setup_lines, fire_lines).
    setup_lines (classes, functions, descriptors) never touch the call expression's effect
    until something actually invokes it, so they're safe to place
    anywhere earlier in a block.
    fire_lines is the final statement(s) that actually walk the chain, meant to run exactly once.

repeatable_call_expr()
    Returns -> (setup_lines, expr).
    expr is a single, self-contained expression that performs
    the call as a side effect every time it's evaluated -> for sites
    that need the SAME disguised call reachable from several
    independent checkpoints (e.g. half a dozen anti-debug checks that
    all react the same way) without making a fresh set of
    classes per checkpoint.

deferred_reaction_lines()
    Returns -> (setup_lines, mark_expr).
    Neither family above changes *when* the call happens -> both still
    fire at the point something in the normal flow of execution
    reaches them. This one arms a reaction that fires later, at a
    point structurally AND temporally decoupled from wherever it got
    armed: interpreter shutdown, a self-rescheduling background timer,
    or the interpreter's own next real garbage-collection pass.
    mark_expr is the cheap, innocuous statement a check site uses to
    arm it; it produces no visible effect of its own.

All three are keyed off using the same rng/reserved_names convention as the
rest of the obfuscation stack, and collectively span several distinct
families (metaclasses, descriptors, context managers, rich
comparison, attribute/item access, the copy/pickle hooks, refcounting
finalization, and interpreter-shutdown/GC instrumentation) so a reader
who's worked out one disguise gains nothing against the others.
"""
from __future__ import annotations
import random
from .namegen import random_confusable_name
from .strcodec import _hidden_str_expr, _hidden_import_attr, _render_int

_ONE_SHOT_STYLE_COUNT = 11
_REPEATABLE_STYLE_COUNT = 4
_DEFERRED_STYLE_COUNT = 3


def one_shot_call_lines(
    call_expr: str, rng: random.Random, style: int, reserved_names: set,
) -> tuple[list[str], list[str]]:
    """
    A number of different ways to reach "call_expr" exactly once, each
    as a side effect of ordinary-looking Python rather than a
    direct, bare statement.
    """
    used = reserved_names
    style = style % _ONE_SHOT_STYLE_COUNT

    if style == 0:
        # Metaclass __new__: fires at class-creation time, i.e. the
        # moment the "class cls_name(metaclass=meta_name): pass"
        # statement itself executes.
        meta_name, cls_name, fn_name = (
            random_confusable_name(rng, used, length=rng.randint(7, 12)) for _ in range(3)
        )
        p_mcs, p_name, p_bases, p_ns = (random_confusable_name(rng, used, length=rng.randint(4, 6)) for _ in range(4))
        new_str = _hidden_str_expr("__new__", rng)
        setup = [
            f"class {meta_name}(type):",
            f"    pass",
            f"def {fn_name}({p_mcs}, {p_name}, {p_bases}, {p_ns}):",
            f"    {call_expr}",
            f"    return getattr(type, {new_str})({p_mcs}, {p_name}, {p_bases}, {p_ns})",
            f"setattr({meta_name}, {new_str}, {fn_name})",
        ]
        fire = [
            f"class {cls_name}(metaclass={meta_name}):",
            f"    pass",
        ]
        return setup, fire

    elif style == 1:
        # Descriptor __set_name__: fires when the owning class body
        # finishes executing and binds the descriptor instance to a
        # name.
        desc_name, cls_name, attr_name, fn_name = (
            random_confusable_name(rng, used, length=rng.randint(6, 12)) for _ in range(4)
        )
        p_self, p_owner, p_ownname = (random_confusable_name(rng, used, length=rng.randint(4, 6)) for _ in range(3))
        set_name_str = _hidden_str_expr("__set_name__", rng)
        setup = [
            f"class {desc_name}:",
            f"    pass",
            f"def {fn_name}({p_self}, {p_owner}, {p_ownname}):",
            f"    {call_expr}",
            f"setattr({desc_name}, {set_name_str}, {fn_name})",
        ]
        fire = [
            f"class {cls_name}:",
            f"    {attr_name} = {desc_name}()",
        ]
        return setup, fire

    elif style == 2:
        # __init_subclass__: fires when a subclass of base_name is
        # defined.
        base_name, sub_name, fn_name = (
            random_confusable_name(rng, used, length=rng.randint(7, 12)) for _ in range(3)
        )
        p_cls, p_kw = (random_confusable_name(rng, used, length=rng.randint(4, 6)) for _ in range(2))
        init_sub_str = _hidden_str_expr("__init_subclass__", rng)
        classmethod_ref = _hidden_import_attr("builtins", "classmethod", rng)
        setup = [
            f"class {base_name}:",
            f"    pass",
            f"def {fn_name}({p_cls}, **{p_kw}):",
            f"    {call_expr}",
            f"setattr({base_name}, {init_sub_str}, {classmethod_ref}({fn_name}))",
        ]
        fire = [
            f"class {sub_name}({base_name}):",
            f"    pass",
        ]
        return setup, fire

    elif style == 3:
        # Metaclass __call__: distinct from style 0 -> __new__ fires
        # at class creation, this fires on instantiation, so the
        # defining "class cls_name(metaclass=meta_name): pass" is
        # itself an inert setup and the real trigger is the later call.
        meta_name, cls_name, fn_name = (
            random_confusable_name(rng, used, length=rng.randint(7, 12)) for _ in range(3)
        )
        p_mcs, p_args, p_kwargs = (random_confusable_name(rng, used, length=rng.randint(4, 6)) for _ in range(3))
        call_str = _hidden_str_expr("__call__", rng)
        setup = [
            f"class {meta_name}(type):",
            f"    pass",
            f"def {fn_name}({p_mcs}, *{p_args}, **{p_kwargs}):",
            f"    {call_expr}",
            f"    return type.__call__({p_mcs}, *{p_args}, **{p_kwargs})",
            f"setattr({meta_name}, {call_str}, {fn_name})",
            f"class {cls_name}(metaclass={meta_name}):",
            f"    pass",
        ]
        fire = [f"{cls_name}()"]
        return setup, fire

    elif style == 4:
        # Context manager __exit__: fires when a "with" block tied to it unwinds.
        ctx_name, enter_fn, exit_fn = (
            random_confusable_name(rng, used, length=rng.randint(6, 12)) for _ in range(3)
        )
        p_self, p_exc = (random_confusable_name(rng, used, length=rng.randint(4, 6)) for _ in range(2))
        enter_str = _hidden_str_expr("__enter__", rng)
        exit_str = _hidden_str_expr("__exit__", rng)
        setup = [
            f"class {ctx_name}:",
            f"    pass",
            f"def {enter_fn}({p_self}):",
            f"    return {p_self}",
            f"def {exit_fn}({p_self}, *{p_exc}):",
            f"    {call_expr}",
            f"    return False",
            f"setattr({ctx_name}, {enter_str}, {enter_fn})",
            f"setattr({ctx_name}, {exit_str}, {exit_fn})",
        ]
        fire = [
            f"with {ctx_name}():",
            f"    pass",
        ]
        return setup, fire

    elif style == 5:
        # __class_getitem__: fires on a plain subscript of the class,
        # e.g. "cls_name[0]" -> reads like leftover generic-typing
        # syntax rather than anything executable.
        cls_name, fn_name, tmp_name = (
            random_confusable_name(rng, used, length=rng.randint(7, 12)) for _ in range(3)
        )
        p_cls, p_item = (random_confusable_name(rng, used, length=rng.randint(4, 6)) for _ in range(2))
        cgi_str = _hidden_str_expr("__class_getitem__", rng)
        classmethod_ref = _hidden_import_attr("builtins", "classmethod", rng)
        setup = [
            f"class {cls_name}:",
            f"    pass",
            f"def {fn_name}({p_cls}, {p_item}):",
            f"    {call_expr}",
            f"    return {p_item}",
            f"setattr({cls_name}, {cgi_str}, {classmethod_ref}({fn_name}))",
        ]
        fire = [f"{tmp_name} = {cls_name}[0]"]
        return setup, fire

    elif style == 6:
        # Rich comparison: an __eq__ override fired by an ordinary
        # "!=" comparison, deliberately shaped like the real
        # length-verification guards elsewhere in the stub -> chains
        # onto that existing visual pattern instead of introducing a
        # new one.
        sent_name, fn_name, inst_name = (
            random_confusable_name(rng, used, length=rng.randint(7, 12)) for _ in range(3)
        )
        p_self, p_other = (random_confusable_name(rng, used, length=rng.randint(4, 6)) for _ in range(2))
        eq_str = _hidden_str_expr("__eq__", rng)
        decoy_len = rng.randint(2, 97)
        decoy_lit = _render_int(decoy_len, rng)
        setup = [
            f"class {sent_name}:",
            f"    pass",
            f"def {fn_name}({p_self}, {p_other}):",
            f"    {call_expr}",
            f"    return False",
            f"setattr({sent_name}, {eq_str}, {fn_name})",
            f"{inst_name} = {sent_name}()",
        ]
        fire = [f"if {inst_name} != {decoy_lit}:",
                f"    pass"]
        return setup, fire

    elif style == 7:
        # __reduce__: fires when something copies the instance (e.g.
        # copy.copy(), which falls back to __reduce__ when no
        # __copy__/__deepcopy__ is defined).
        cls_name, fn_name, tmp_name = (
            random_confusable_name(rng, used, length=rng.randint(7, 12)) for _ in range(3)
        )
        p_self = random_confusable_name(rng, used, length=rng.randint(4, 6))
        reduce_str = _hidden_str_expr("__reduce__", rng)
        str_ref = _hidden_import_attr("builtins", "str", rng)
        copy_ref = _hidden_import_attr("copy", "copy", rng)
        empty_str = _hidden_str_expr("", rng)
        setup = [
            f"class {cls_name}:",
            f"    pass",
            f"def {fn_name}({p_self}):",
            f"    {call_expr}",
            f"    return ({str_ref}, ({empty_str},))",
            f"setattr({cls_name}, {reduce_str}, {fn_name})",
        ]
        fire = [f"{tmp_name} = {copy_ref}({cls_name}())"]
        return setup, fire

    elif style == 8:
        # weakref callback: CPython's refcounting GC deallocates the
        # throwaway referent the instant the wrapper function that
        # created it returns (nothing else references it).
        cls_name, cb_name, arm_name = (
            random_confusable_name(rng, used, length=rng.randint(7, 12)) for _ in range(3)
        )
        p_ref = random_confusable_name(rng, used, length=rng.randint(4, 6))
        obj_name = random_confusable_name(rng, used, length=rng.randint(4, 6))
        weakref_ref = _hidden_import_attr("weakref", "ref", rng)
        setup = [
            f"class {cls_name}:",
            f"    pass",
            f"def {cb_name}({p_ref}):",
            f"    {call_expr}",
            f"def {arm_name}():",
            f"    {obj_name} = {cls_name}()",
            f"    return {weakref_ref}({obj_name}, {cb_name})",
        ]
        fire = [f"{arm_name}()"]
        return setup, fire

    elif style == 9:
        # __del__ finalizer: is a bare expression statement that has no
        # assignment and that means the instance's only reference dies the
        # moment the statement finishes. __del__ fires synchronously
        # right there and is structurally hidden from the call site.
        cls_name, fn_name = (
            random_confusable_name(rng, used, length=rng.randint(7, 12)) for _ in range(2)
        )
        p_self = random_confusable_name(rng, used, length=rng.randint(4, 6))
        del_str = _hidden_str_expr("__del__", rng)
        setup = [
            f"class {cls_name}:",
            f"    pass",
            f"def {fn_name}({p_self}):",
            f"    {call_expr}",
            f"setattr({cls_name}, {del_str}, {fn_name})",
        ]
        fire = [f"{cls_name}()"]
        return setup, fire

    else:
        # weakref.finalize: the API actually meant for this (vs.
        # __del__/weakref.ref) -> the same prompt-collection shape as
        # style 8 with a different entry point, and the callback takes no
        # arguments at all. So there's nothing in the signature that
        # even hints at what triggered it.
        cls_name, cb_name, arm_name, obj_name = (
            random_confusable_name(rng, used, length=rng.randint(7, 12)) for _ in range(4)
        )
        weakref_finalize = _hidden_import_attr("weakref", "finalize", rng)
        setup = [
            f"class {cls_name}:",
            f"    pass",
            f"def {cb_name}():",
            f"    {call_expr}",
            f"def {arm_name}():",
            f"    {obj_name} = {cls_name}()",
            f"    {weakref_finalize}({obj_name}, {cb_name})",
        ]
        fire = [f"{arm_name}()"]
        return setup, fire


def repeatable_call_expr(
    call_expr: str, rng: random.Random, style: int, reserved_names: set,
) -> tuple[list[str], str]:
    """
    Like one_shot_call_lines, but the second return value is a bare
    expression safe to embed inline (e.g. in "if cond: {expr}", a
    try/except one-liner, or a ternary) and safe to evaluate more than
    once. Each evaluation re-runs call_expr as a side effect. For
    sites where the same disguised reaction needs to be reachable from
    several independent checkpoints without creating a fresh set of
    classes per checkpoint.
    """
    used = reserved_names
    style = style % _REPEATABLE_STYLE_COUNT

    if style == 0:
        # Metaclass __call__: every "cls_name()" re-invocation re-runs call_expr.
        meta_name, cls_name, fn_name = (
            random_confusable_name(rng, used, length=rng.randint(7, 12)) for _ in range(3)
        )
        p_mcs, p_args, p_kwargs = (random_confusable_name(rng, used, length=rng.randint(4, 6)) for _ in range(3))
        call_str = _hidden_str_expr("__call__", rng)
        setup = [
            f"class {meta_name}(type):",
            f"    pass",
            f"def {fn_name}({p_mcs}, *{p_args}, **{p_kwargs}):",
            f"    {call_expr}",
            f"    return type.__call__({p_mcs}, *{p_args}, **{p_kwargs})",
            f"setattr({meta_name}, {call_str}, {fn_name})",
            f"class {cls_name}(metaclass={meta_name}):",
            f"    pass",
        ]
        return setup, f"{cls_name}()"

    elif style == 1:
        # __getattr__: fires on any attribute access the instance
        # doesn't already have -> each access of that one undefined
        # name re-runs call_expr.
        cls_name, fn_name, inst_name, attr_name = (
            random_confusable_name(rng, used, length=rng.randint(6, 12)) for _ in range(4)
        )
        p_self, p_name = (random_confusable_name(rng, used, length=rng.randint(4, 6)) for _ in range(2))
        getattr_str = _hidden_str_expr("__getattr__", rng)
        setup = [
            f"class {cls_name}:",
            f"    pass",
            f"def {fn_name}({p_self}, {p_name}):",
            f"    {call_expr}",
            f"    return None",
            f"setattr({cls_name}, {getattr_str}, {fn_name})",
            f"{inst_name} = {cls_name}()",
        ]
        return setup, f"{inst_name}.{attr_name}"

    elif style == 2:
        # __getitem__: every subscript of the instance re-runs call_expr.
        cls_name, fn_name, inst_name = (
            random_confusable_name(rng, used, length=rng.randint(7, 12)) for _ in range(3)
        )
        p_self, p_item = (random_confusable_name(rng, used, length=rng.randint(4, 6)) for _ in range(2))
        getitem_str = _hidden_str_expr("__getitem__", rng)
        idx_lit = _render_int(rng.randint(0, 255), rng)
        setup = [
            f"class {cls_name}:",
            f"    pass",
            f"def {fn_name}({p_self}, {p_item}):",
            f"    {call_expr}",
            f"    return {p_item}",
            f"setattr({cls_name}, {getitem_str}, {fn_name})",
            f"{inst_name} = {cls_name}()",
        ]
        return setup, f"{inst_name}[{idx_lit}]"

    else:
        # __reduce__ via copy.copy(): every copy of the instance re-runs call_expr.
        cls_name, fn_name, inst_name = (
            random_confusable_name(rng, used, length=rng.randint(7, 12)) for _ in range(3)
        )
        p_self = random_confusable_name(rng, used, length=rng.randint(4, 6))
        reduce_str = _hidden_str_expr("__reduce__", rng)
        str_ref = _hidden_import_attr("builtins", "str", rng)
        copy_ref = _hidden_import_attr("copy", "copy", rng)
        empty_str = _hidden_str_expr("", rng)
        setup = [
            f"class {cls_name}:",
            f"    pass",
            f"def {fn_name}({p_self}):",
            f"    {call_expr}",
            f"    return ({str_ref}, ({empty_str},))",
            f"setattr({cls_name}, {reduce_str}, {fn_name})",
            f"{inst_name} = {cls_name}()",
        ]
        return setup, f"{copy_ref}({inst_name})"


def deferred_reaction_lines(
    call_expr: str, rng: random.Random, style: int, reserved_names: set,
    condition_expr: str | None = None,
) -> tuple[list[str], str | None]:
    """
    Arms a reaction that fires later at a point structurally AND
    temporally decoupled from wherever it gets triggered. Takes advantage of
    normal interpreter shutdown, a self-rescheduling background timer on an
    independent thread, or the interpreter's own next real garbage-
    collection pass.

    If condition_expr is given, it's used as the trigger test directly
    (for callers that already maintain their own shared signal, e.g.
    gnolly.poison's accumulator).
    If omitted, this function creates and owns a private one-element
    list as its flag; mark_expr is the single statement that arms it,
    safe to embed inline ("if cond: {mark_expr}") at as many
    independent check sites as needed.

    Either way, mark_expr/condition_expr never calls call_expr
    directly and produces no visible effect of its own -> a reader
    single-stepping the check that fails sees nothing happen. The
    reaction only surfaces later.
    """
    used = reserved_names
    style = style % _DEFERRED_STYLE_COUNT

    if condition_expr is not None:
        test_expr = condition_expr
        flag_setup: list[str] = []
        mark_expr = None
    else:
        flag_name = random_confusable_name(rng, used, length=rng.randint(6, 11))
        test_expr = f"{flag_name}[0]"
        flag_setup = [f"{flag_name} = [0]"]
        mark_expr = f"{flag_name}[0] = 1"

    if style == 0:
        # atexit.register: fires only at normal interpreter exit ->
        # catches an attacker who got past every earlier check and had
        # the program running right up until it would have exited.
        cb_name = random_confusable_name(rng, used, length=rng.randint(7, 12))
        atexit_register = _hidden_import_attr("atexit", "register", rng)
        setup = flag_setup + [
            f"def {cb_name}():",
            f"    if {test_expr}:",
            f"        {call_expr}",
            f"{atexit_register}({cb_name})",
        ]
        return setup, mark_expr

    elif style == 1:
        # Self-rescheduling background timer: an independent thread
        # polls the test on a randomized interval for the life of the
        # process, re-arming itself each time it finds nothing.
        # This is a different call stack and a different thread with no relationship to
        # whatever set (or will set) the signal.
        timer_cls = _hidden_import_attr("threading", "Timer", rng)
        rand_fn = _hidden_import_attr("random", "uniform", rng)
        daemon_str = _hidden_str_expr("daemon", rng)
        start_str = _hidden_str_expr("start", rng)
        cb_name, delay_fn, sched_fn, tmr_var = (
            random_confusable_name(rng, used, length=rng.randint(7, 12)) for _ in range(4)
        )
        min_d = round(rng.uniform(0.05, 0.3), 3)
        max_d = round(min_d + rng.uniform(0.2, 1.0), 3)
        setup = flag_setup + [
            f"def {delay_fn}():",
            f"    return {rand_fn}({min_d!r}, {max_d!r})",
            f"def {sched_fn}():",
            f"    {tmr_var} = {timer_cls}({delay_fn}(), {cb_name})",
            f"    setattr({tmr_var}, {daemon_str}, True)",
            f"    getattr({tmr_var}, {start_str})()",
            f"def {cb_name}():",
            f"    if {test_expr}:",
            f"        {call_expr}",
            f"    else:",
            f"        {sched_fn}()",
            f"{sched_fn}()",
        ]
        return setup, mark_expr

    else:
        # gc.callbacks: appends to CPython's own list of functions the
        # real garbage collector calls at the start of every
        # collection pass it runs on its own, driven by ordinary
        # allocation activity elsewhere in the program.
        gc_callbacks = _hidden_import_attr("gc", "callbacks", rng)
        append_str = _hidden_str_expr("append", rng)
        start_phase_str = _hidden_str_expr("start", rng)
        cb_name, p_phase, p_info = (
            random_confusable_name(rng, used, length=rng.randint(6, 11)) for _ in range(3)
        )
        setup = flag_setup + [
            f"def {cb_name}({p_phase}, {p_info}):",
            f"    if {p_phase} == {start_phase_str} and {test_expr}:",
            f"        {call_expr}",
            f"getattr({gc_callbacks}, {append_str})({cb_name})",
        ]
        return setup, mark_expr
