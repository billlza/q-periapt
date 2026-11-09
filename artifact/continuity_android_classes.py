"""Read bounded Java 11 class identities and the actual Continuity JNI surface.

ClassFile/constant-pool/method framing follows JVMS chapter 4:
https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html
This reader checks packaging and JNI identities; the JVM owns bytecode validation.
"""
from __future__ import annotations

import re


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def class_identity(data: bytes) -> tuple[str, dict[tuple[str, str], int]]:
    require(10 <= len(data) <= 4 * 1024 * 1024, "class file size differs")
    offset = 0

    def take(size):
        nonlocal offset
        require(size >= 0 and offset + size <= len(data), "truncated class file")
        value = data[offset:offset + size]
        offset += size
        return value

    def integer(size):
        return int.from_bytes(take(size), "big")

    require(take(4) == b"\xca\xfe\xba\xbe" and integer(2) == 0 and integer(2) == 55,
            "classes must use the retained Java 11 class format")
    count = integer(2)
    require(count > 1, "empty class constant pool")
    pool = [None] * count
    index = 1
    while index < count:
        tag = integer(1)
        if tag == 1:
            pool[index] = (tag, take(integer(2)))
        elif tag in {7, 8, 16, 19, 20}:
            pool[index] = (tag, integer(2))
        elif tag in {3, 4, 9, 10, 11, 12, 17, 18}:
            take(4)
        elif tag in {5, 6}:
            require(index + 1 < count, "wide constant overruns pool")
            take(8)
            index += 1
        elif tag == 15:
            take(3)
        else:
            raise ValueError("unsupported class constant-pool tag")
        index += 1

    def text(index):
        require(0 < index < count and pool[index] is not None and pool[index][0] == 1,
                "class identity does not reference a UTF-8 constant")
        # These package/name/descriptor identities are ASCII. Other modified
        # UTF-8 constants are retained without interpreting their string value.
        return pool[index][1].decode("ascii")

    def attributes():
        names = []
        for _ in range(integer(2)):
            names.append(text(integer(2)))
            take(integer(4))
        require(len(names) == len(set(names)), "duplicate class member attributes")
        return names

    integer(2)
    this = integer(2)
    require(0 < this < count and pool[this] is not None and pool[this][0] == 7,
            "class has no declared class identity")
    name = text(pool[this][1])
    integer(2)
    take(2 * integer(2))
    for _ in range(integer(2)):
        integer(2); text(integer(2)); text(integer(2)); attributes()
    methods = {}
    for _ in range(integer(2)):
        flags, method, descriptor = integer(2), text(integer(2)), text(integer(2))
        key = method, descriptor
        require(key not in methods, "duplicate class method identity")
        method_attributes = attributes()
        require(("Code" in method_attributes) == (not bool(flags & (0x0100 | 0x0400))),
                "method code/native/abstract identity differs")
        methods[key] = flags
    attributes()
    require(offset == len(data), "class has trailing bytes")
    return name, methods


def jni_contract(source: str) -> tuple[dict[str, str], dict[str, str]]:
    blocks = re.findall(r"const JNINativeMethod methods\[\] = \{(.*?)\n    \};", source, re.S)
    require(len(blocks) == 1, "JNI registration array differs")
    rows = re.findall(r'\{"([A-Za-z][A-Za-z0-9_]*)", "([^"]+)", \(void \*\)[a-z_]+\}', blocks[0])
    remainder = re.sub(r'\{"([A-Za-z][A-Za-z0-9_]*)", "([^"]+)", \(void \*\)[a-z_]+\}', '', blocks[0])
    require(not remainder.replace(',', '').strip() and len(rows) == 23
            and len(dict(rows)) == len(rows), "JNI method registration contract differs")
    callbacks = re.findall(r'GetStaticMethodID\(env, local, "([A-Za-z][A-Za-z0-9_]*)", "([^"]+)"\)', source)
    require(len(callbacks) == 3 and len(dict(callbacks)) == 3
            and source.count('FindClass(env, "dev/qperiapt/continuity/android/Native")') == 1,
            "JNI callback or class binding differs")
    return dict(rows), dict(callbacks)


def verify_classes(entries: dict[str, bytes], java_sources: set[str], bridge: str) -> dict:
    prefix = "dev/qperiapt/continuity/android/"
    require(0 < len(entries) <= 1024, "class inventory is empty or oversized")
    expected = {name.removesuffix(".java") for name in java_sources}
    require(all(name.startswith(prefix) and name.endswith(".java") for name in java_sources),
            "Java source namespace differs")
    top_level, native_methods, native_identity = set(), {}, None
    for path, data in entries.items():
        require(path.endswith(".class") and path.startswith(prefix), "unexpected classes.jar entry")
        name, methods = class_identity(data)
        require(path == name + ".class" and name.split('$', 1)[0] in expected,
                "class path or source identity differs")
        if '$' not in name:
            top_level.add(name)
        declared_native = {method: descriptor for (method, descriptor), flags in methods.items() if flags & 0x0100}
        require(len(declared_native) == sum(bool(flags & 0x0100) for flags in methods.values()),
                "native methods may not overload names")
        if name == prefix + "Native":
            native_identity = methods
            native_methods = declared_native
        else:
            require(not declared_native, "native method outside the registered class")
    require(top_level == expected and native_identity is not None, "missing source class or JNI class")
    registered, callbacks = jni_contract(bridge)
    require(native_methods == registered, "class native descriptors differ from JNI registration")
    for method, descriptor in registered.items():
        require(native_identity[method, descriptor] & 0x0008, "registered native method is not static")
    for method, descriptor in callbacks.items():
        flags = native_identity.get((method, descriptor), 0)
        require(flags & 0x0008 and not flags & (0x0100 | 0x0400), "JNI callback descriptor or static code differs")
    return {"classes": len(entries), "native_methods": len(registered), "callbacks": callbacks,
            "class_major": 55}
