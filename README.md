# Root2PoC Codex 분석 코어

Root2PoC는 허가된 폐쇄형 소프트웨어의 네이티브 취약점을 분석할 때 사용하는
대상 독립적 Codex 실행 코어입니다.

```text
LLM + IDA MCP로 가설 수립
        -> 필요할 때만 최소 native/CDB 실험
        -> 관찰 결과와 claim 경계 기록
        -> 다음 분석 결정
```

이 공개 저장소에는 공통 규칙, 선택형 디버거 검증 skill, 컨텍스트 복구
runtime, schema, 테스트와 범용 template만 둡니다. 실제 분석 대상, 바이너리,
PoC와 취약점 증거는 로컬에만 보관하며 Git 기록에 포함하지 않습니다.

## 저장소 구성

- `AGENTS.md`: 프로젝트 공통 범위, 증거, 안전 및 claim 경계
- `.agents/skills/cdb-native-validation/`: 필요할 때만 사용하는 native debugger 검증 skill
- `.codex/hooks.json`: 프로젝트 로컬 컨텍스트 lifecycle hook
- `research/tools/closed_source_context/`: capture, capsule, guard, retrieval, evaluation 및 테스트
- `research/templates/closed-source-rce/`: 범용 discovery prompt와 target instance template

## 로컬 연구 공간 만들기

clone 또는 worktree 하나에는 활성 대상을 하나만 두는 것을 권장합니다. 활성
prompt와 target instance는 의도적으로 Git에서 제외됩니다.

```bash
mkdir -p research/active/closed-source-rce
cp research/templates/closed-source-rce/DISCOVERY-PROMPT.md \
  research/active/closed-source-rce/DISCOVERY-PROMPT.md
cp -R research/templates/closed-source-rce/target-instance \
  research/active/closed-source-rce/example-target
```

분석 전에 prompt의 대괄호 항목과 target metadata를 실제 대상에 맞게 수정합니다.
기존 target workspace 위에 위 복사 명령을 다시 실행하지 마세요.

저장소 루트에서 Codex를 시작하고 프로젝트 hook을 검토·신뢰한 뒤 다음 명령으로
설치를 확인합니다.

```bash
python3 -B -m unittest discover -s research/tools/closed_source_context/tests -v
python3 research/tools/repository_preflight.py
```

사전점검은 Git index를 기준으로 검사하므로 파일을 stage하거나 commit한 뒤 실행할
때 가장 정확합니다.

## 팀 협업 방식

사람마다 고정 브랜치를 하나씩 오래 유지하기보다 작업마다 짧은 브랜치를 만듭니다.
이 방식이 충돌을 줄이고 어떤 변경을 왜 리뷰하는지 명확하게 남깁니다.

```bash
git switch main
git pull --ff-only
git switch -c docs/readme-ko       # 예시
# 또는 tool/context-runtime, research/generic-parser-helper 등
```

권장 흐름은 다음과 같습니다.

1. 최신 `main`에서 작업 단위 브랜치를 만듭니다.
2. 대상 독립적인 코드·문서·테스트만 commit합니다.
3. 원격 브랜치로 push하고 Pull Request를 엽니다.
4. 마지막 변경을 올린 사람 이외의 팀원에게 최소 1회 승인을 받습니다.
5. 오래된 승인은 새 push 시 무효화하고, 리뷰 대화를 모두 해결한 뒤 merge합니다.
6. `main` 직접 push, force push, branch 삭제는 허용하지 않습니다.

`main` 보호 규칙은 저장소 관리자에게도 적용하는 것을 기본으로 합니다. 따라서
관리자를 포함한 모든 팀원이 동일한 PR 리뷰 절차를 따릅니다.

## 공개 저장소 경계

다음 자료는 stage하거나 commit하지 않습니다.

- 활성 discovery prompt와 target metadata
- evidence, observation, finding, `llm-log.md`
- PoC, control, corpus, dump
- vendor 바이너리와 실제 문서 입력
- IDA database와 debugger/session 자료
- credential, 접속 정보, machine-specific path

target 전용으로 작성된 script도 바로 공유하지 않습니다. 대상 독립적으로 일반화하고
테스트를 추가한 뒤 의도적으로 코어에 승격한 경우에만 Pull Request에 포함합니다.

runtime의 보장 범위와 검증 경계는
[`research/tools/closed_source_context/CONTRACT.md`](research/tools/closed_source_context/CONTRACT.md)에
정리되어 있습니다.
