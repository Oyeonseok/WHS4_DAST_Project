# Attack-Validator-Report 변경 이력

## 구조 원칙

**LLM이 공격을 수행하고, Python은 결과 저장만 한다.**
- Python 공격 로직 코드 없음 (idor.py, engine.py, generator.py 삭제)
- 모든 판단/실행/해석은 SKILL.md를 로드한 LLM Agent가 수행
- LLM은 DB를 직접 건드리지 않음 — JSON 반환 → 오케스트레이터가 DB 저장
- Codex CLI `--output-schema`로 구조화된 JSON 출력 강제
- Recon 코드: 변경 없음

## 파일 목록

### 문서
| 파일 | 설명 |
|---|---|
| `docs/attack-validator-report/ARCHITECTURE.md` | 전체 아키텍처, Codex CLI 실행 패턴, 데이터 흐름 설계 |
| `docs/attack-validator-report/CHANGELOG.md` | 이 파일 |

### 오케스트레이션
| 파일 | 설명 |
|---|---|
| `src/aidast/orchestration/attack.py` | `AttackCoordinator` — Attack→Validator→Report 전체 파이프라인 오케스트레이터. Recon DB에서 데이터 추출, LLM 결과 수신, DB 저장, 보고서 파일 저장 |

### LLM Agent 실행
| 파일 | 설명 |
|---|---|
| `src/aidast/agents/main.py` | `_run_attack_agent()` 메서드 추가 — shell 활성화된 Codex CLI 실행 (기존 메서드 수정 없음) |

### Pydantic Output Schema
| 파일 | 설명 |
|---|---|
| `src/aidast/attack/models.py` | `AttackResult`, `ValidationResult`, `ReportResult` — Codex `--output-schema`용 Pydantic 모델 |

### DB 저장
| 파일 | 설명 |
|---|---|
| `src/aidast/attack/__init__.py` | Attack 패키지 |
| `src/aidast/attack/db.py` | findings, attack_requests, validations 테이블 스키마 + CRUD 헬퍼. 트랜잭션 저장, 응답 본문 10,000자 자름, FK 인덱스 |

### SKILL.md (LLM Agent 지침 — 모든 공격/검증/보고 로직이 여기에)
| 파일 | 설명 |
|---|---|
| `src/aidast/skills/attack/idor/SKILL.md` | IDOR 블랙박스 동적 분석 (후보 선별, curl로 HTTP 전송, 응답 해석, 판정, 증거 수집). JSON 반환 |
| `src/aidast/skills/validator/SKILL.md` | 7 Gate Question 검증 (curl로 재현, 권한 경계, 영향도, 서버 측 검증, 의도된 설계, 스코프, 중복). JSON 반환 |
| `src/aidast/skills/report/SKILL.md` | 버그바운티 보고서 작성 (제목, CVSS, PoC, 영향도, 수정 제안). JSON 반환 |

### DB 스키마 추가 (기존 recon 테이블 수정 없음)
| 테이블 | 설명 |
|---|---|
| `findings` | 취약점 발견 기록. `endpoint_id` nullable. `status` 컬럼으로 confirmed/rejected/inconclusive 추적 |
| `attack_requests` | 공격 시 보낸 요청/응답 증거. role별(user_a/user_b/unauthenticated) 기록 |
| `validations` | 7 Gate Question 판정 결과. gate_results는 JSON, confidence는 0.0~1.0 |

### 미사용 패키지 (빈 __init__.py만 존재)
| 파일 | 설명 |
|---|---|
| `src/aidast/validator/__init__.py` | 별도 Python 로직 없음 (LLM이 SKILL.md로 수행) |
| `src/aidast/report/__init__.py` | 별도 Python 로직 없음 (LLM이 SKILL.md로 수행) |

## 삭제된 파일

| 파일 | 삭제 이유 |
|---|---|
| `attack/idor.py` | Python이 공격 로직을 갖고 있었음 → LLM이 직접 수행하므로 불필요 |
| `attack/models.py` (초기 버전) | Python 공격 엔진용 Pydantic 모델 → output schema 전용 models.py로 교체 |
| `validator/engine.py` | Python이 7 Gate 판정을 했음 → LLM이 직접 수행하므로 불필요 |
| `validator/models.py` | Python 검증 엔진용 모델 → attack/models.py의 ValidationResult로 통합 |
| `validator/db.py` | attack/db.py 재수출만 하던 파일 → 불필요 |
| `report/generator.py` | Python이 보고서를 생성했음 → LLM이 직접 작성하므로 불필요 |
| `report/models.py` | Python 보고서용 모델 → attack/models.py의 ReportResult로 통합 |
