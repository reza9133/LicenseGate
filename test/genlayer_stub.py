"""
A minimal, dependency-free stand-in for the real `genlayer` GenVM SDK.

This is NOT a reimplementation of GenVM's consensus, fee, or storage
semantics. Its only job is to let the real files in `contracts/` be imported
and executed as plain Python, so the tests in this directory exercise the
shipped logic rather than a separate copy of it. The official checks
(`genvm-lint check`) are what validate the contracts against the real SDK;
these tests validate behaviour.

What it covers: Address (with format validation), the sized integer aliases,
DynArray / TreeMap with zero-initialised storage semantics, allow_storage,
gl.Contract, gl.public.view / write, gl.message, gl.vm.UserError / Return /
run_nondet_unsafe, gl.nondet.web.get / exec_prompt and gl.contract_interface.

Two conveniences for chained-contract tests:

  * deploy_and_register() constructs a REAL instance of a contract class and
    registers it under an address, so another contract's typed
    @gl.contract_interface call into that address reaches the live instance
    instead of a hand-written fake.
  * run_nondet_unsafe() runs the leader, then runs the contract's REAL
    validator function against the leader's result (a leader error is handed
    to the validator as the error object, exactly like the real VM does). If
    the validator disagrees, the call raises AssertionError, which is how a
    failed consensus shows up in a single-process test.

Run with:  python3 -m unittest discover -s test -v
"""
import dataclasses
import importlib.util
import sys
import types


ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
_HEX = set("0123456789abcdefABCDEF")


class Address:
    def __init__(self, value=ZERO_ADDRESS):
        s = str(value)
        if not (len(s) == 42 and s.startswith("0x") and all(c in _HEX for c in s[2:])):
            raise ValueError("invalid address: " + s)
        self._value = s

    def __str__(self):
        return self._value

    def __repr__(self):
        return "Address(" + self._value + ")"

    def __eq__(self, other):
        return str(self).lower() == str(other).lower()

    def __hash__(self):
        return hash(str(self).lower())


_INT_ALIASES = (
    ["u" + str(n) for n in range(8, 257, 8)]
    + ["i" + str(n) for n in range(8, 257, 8)]
    + ["bigint"]
)


class DynArray(list):
    def __class_getitem__(cls, item):
        return cls


class _ParamTreeMap(dict):
    _value_type = None

    def get(self, key, default=None):
        return dict.get(self, key, default)

    def get_or_insert_default(self, key):
        if key not in self:
            self[key] = _zero_value(self.__class__._value_type)
        return self[key]


class TreeMap(_ParamTreeMap):
    def __class_getitem__(cls, item):
        key_type, value_type = item
        return type("TreeMap", (_ParamTreeMap,), {"_key_type": key_type, "_value_type": value_type})


def allow_storage(cls):
    return cls


def _zero_value(tp):
    """Mirrors the documented GenVM storage defaults (integers 0, bool False,
    str "", Address zero, DynArray [], TreeMap {}) and zero-constructs nested
    @allow_storage dataclasses recursively."""
    if tp is None:
        return None
    if tp is bool:
        return False
    if tp is int:
        return 0
    if tp is str:
        return ""
    if tp is Address:
        return Address(ZERO_ADDRESS)
    if isinstance(tp, type) and issubclass(tp, _ParamTreeMap):
        return tp()
    if isinstance(tp, type) and issubclass(tp, DynArray):
        return tp()
    if dataclasses.is_dataclass(tp):
        kwargs = {}
        for f in dataclasses.fields(tp):
            kwargs[f.name] = _zero_value(f.type)
        return tp(**kwargs)
    return None


class UserError(Exception):
    def __init__(self, message=""):
        super().__init__(message)
        self.message = message


class VMError(Exception):
    pass


class Return:
    def __init__(self, calldata):
        self.calldata = calldata


def run_nondet_unsafe(leader_fn, validator_fn):
    try:
        result = leader_fn()
    except UserError as e:
        # The leader failed: the validator judges the error object itself.
        if not validator_fn(e):
            raise AssertionError("validator_fn rejected the leader's error: " + str(e.message))
        raise
    if not validator_fn(Return(result)):
        raise AssertionError(
            "validator_fn rejected the leader's result -- consensus would fail and rotate the leader")
    return result


message = types.SimpleNamespace(
    sender_address=Address(ZERO_ADDRESS),
    value=0,
    contract_address=Address(ZERO_ADDRESS),
    chain_id=0,
)


def _identity(fn):
    return fn


def _write(fn):
    return fn


_write.payable = _identity

public = types.SimpleNamespace(view=_identity, write=_write)

vm = types.SimpleNamespace(UserError=UserError, VMError=VMError, Return=Return,
    Result=object, run_nondet_unsafe=run_nondet_unsafe)


# ---------------------------------------------------------------------------
# Non-deterministic primitives, controlled per test
# ---------------------------------------------------------------------------

class WebResponse:
    def __init__(self, status=200, body=""):
        self.status = status
        self.body = body.encode("utf-8") if isinstance(body, str) else body


NONDET_HOOKS = {
    "web_get": lambda url: WebResponse(404, ""),
    "exec_prompt": lambda prompt, response_format: {},
}

# Every call the contracts make is recorded here so tests can assert on it.
CALLS = {"web": [], "llm": []}


class _Web:
    def get(self, url, **kwargs):
        CALLS["web"].append(url)
        return NONDET_HOOKS["web_get"](url)


class _Nondet:
    def __init__(self):
        self.web = _Web()

    def exec_prompt(self, prompt, response_format=None, **kwargs):
        CALLS["llm"].append(prompt)
        return NONDET_HOOKS["exec_prompt"](prompt, response_format)


nondet = _Nondet()


# ---------------------------------------------------------------------------
# Contract-to-contract calls
# ---------------------------------------------------------------------------

CONTRACT_REGISTRY = {}


class _NullContract:
    def view(self):
        return self

    def __getattr__(self, name):
        def _missing(*args, **kwargs):
            raise AssertionError("no contract registered at this address (method " + name + ")")
        return _missing


def contract_interface(cls):
    def factory(address):
        return CONTRACT_REGISTRY.get(str(address).lower(), _NullContract())
    return factory


class Contract:
    """Zero-initialises every annotated storage field before __init__ runs,
    matching GenVM's "storage starts zero-initialized" behaviour."""

    def __new__(cls, *args, **kwargs):
        instance = object.__new__(cls)
        seen = set()
        for klass in reversed(cls.__mro__):
            ann = klass.__dict__.get("__annotations__", {})
            for name, tp in ann.items():
                if name in seen:
                    continue
                seen.add(name)
                try:
                    object.__setattr__(instance, name, _zero_value(tp))
                except Exception:
                    pass
        return instance


gl = types.SimpleNamespace(
    message=message,
    public=public,
    vm=vm,
    nondet=nondet,
    contract_interface=contract_interface,
    Contract=Contract,
)

_module = types.ModuleType("genlayer")
_module.gl = gl
_module.Address = Address
_module.DynArray = DynArray
_module.TreeMap = TreeMap
_module.allow_storage = allow_storage
for _name in _INT_ALIASES:
    setattr(_module, _name, int)


def install():
    """Point sys.modules['genlayer'] at the stub so `from genlayer import *`
    inside the real contract files resolves against it."""
    sys.modules["genlayer"] = _module


def load_contract(path, module_name):
    """Import a contract file from disk as a real Python module, against the
    stub SDK, and return the module object."""
    install()
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _LiveContractProxy:
    def __init__(self, instance):
        self._instance = instance

    def view(self):
        return self._instance

    def emit(self, *args, **kwargs):
        return self._instance

    def __getattr__(self, name):
        return getattr(self._instance, name)


def deploy_and_register(contract_class, address, *args, **kwargs):
    """Constructs a real instance (running its real __init__ under whatever
    message.sender_address is set) and registers it under `address`, so typed
    interface calls from other contracts reach it. Returns the raw instance."""
    instance = contract_class(*args, **kwargs)
    CONTRACT_REGISTRY[str(address).lower()] = _LiveContractProxy(instance)
    return instance


# ---------------------------------------------------------------------------
# Helpers for tests
# ---------------------------------------------------------------------------

def set_web(pages):
    """pages: {url: (status, body)}. Unknown URLs answer HTTP 404."""
    def hook(url):
        if url in pages:
            status, body = pages[url]
            return WebResponse(status, body)
        return WebResponse(404, "")
    NONDET_HOOKS["web_get"] = hook


def set_llm(fn):
    """fn(prompt) -> dict (or anything). Replaces the model."""
    NONDET_HOOKS["exec_prompt"] = lambda prompt, response_format: fn(prompt)


def reset():
    CONTRACT_REGISTRY.clear()
    CALLS["web"].clear()
    CALLS["llm"].clear()
    NONDET_HOOKS["web_get"] = lambda url: WebResponse(404, "")
    NONDET_HOOKS["exec_prompt"] = lambda prompt, response_format: {}
    message.sender_address = Address(ZERO_ADDRESS)
    message.value = 0
