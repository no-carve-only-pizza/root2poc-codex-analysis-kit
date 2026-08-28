# CDB command and option patterns

Load this reference only when a native candidate already needs CDB commands. Adapt every address, module, bitness, process route, and output path to the exact target.

## Session identity and logging

```text
.logopen /t C:\evidence\session.log
vertarget
lm
|
~
.logclose
```

- Match target and debugger bitness.
- Verify the exact module base and binary identity before using an RVA.
- Record launch, attach, document delivery, process ownership, and cleanup as separate facts.

## Launch and attach controls

```text
cdb executable [arguments]
cdb -hd executable [arguments]
cdb -p <decimal-pid>
cdb -pv -p <decimal-pid>
```

- `-hd` selects the standard heap for a debugger-spawned process. It isolates heap state; it does not prove route equivalence.
- `-pv` is noninvasive attach. It can inspect state but has execution-control limits, so do not select it when the hypothesis requires breakpoints or stepping.
- `-pb` avoids the normal initial break-in request during attach. Use it only when break-in behavior is itself relevant.
- `-g` and `-G` change initial and final breakpoint handling. Record them as event-policy variables.
- `-o` debugs target-created child processes. Verify which process actually consumes the input.
- `-noinh` prevents debugger-created targets from inheriting debugger handles. A debugger-created target can also inherit debugger permissions.

Microsoft references:

- [CDB command-line options](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/cdb-command-line-options)
- [Debugging a user-mode process using CDB](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugging-a-user-mode-process-using-cdb)

## Exceptions and module load

```text
sxe av
sxe ld:targetmodule.dll
g
```

Stop at module load, verify the exact base, then set module-relative breakpoints. Record any `sx*` or `-x*` change because first-chance and second-chance policy changes what the debugger observes.

## Observer-only breakpoints

```text
bu targetmodule+0xRVA
g
r
kv
dd @reg L20
db poi(@reg) L40
```

- Capture state immediately before the suspected instruction when possible.
- Do not modify a register, memory, flags, or instruction pointer in an observer-only breakpoint command.
- For lifetime hypotheses, record pointer identity, thread, stack, and order at install, release/free, and first stale use.

## Heap and dump evidence

```text
!address <address>
!heap -p -a <address>
.dump /ma C:\evidence\first-bad-state.dmp
```

Interpret heap output only for the active allocator mode. Keep PageHeap/AppVerifier evidence separate and restore the original settings after the owned test.

## Mutating experiments

Classify register writes, `e*` or `f*` memory writes, forced return, skipped branches, and debugger-invoked allocation/free as `MUTATING`. Use them to distinguish hypotheses, never as sole evidence of a natural trigger, attacker control, or exploitability.
