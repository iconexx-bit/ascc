# The Leaky Data Lake — fixture scenario

## Провенанс

`RUNBOOK.md` не содержит отдельного нарративного описания сценария
«The Leaky Data Lake» — там нет прозы про «компания X держит бакет так-то».
Есть только разрозненные технические факты (раздел «2. ASCC offline core»),
из которых этот сценарий реконструирован:

- путь `fixtures/leaky_data_lake/{trivy,prowler,checkov}.json`;
- тест `test_terraform_and_arn_collapse_to_same_key`, требующий, чтобы
  `aws_s3_bucket.datalake_raw` (Checkov/Trivy) и `arn:aws:s3:::datalake-raw`
  (Prowler) сходились в один `match_key`;
- метрики: 16 сырых находок / 3 инструмента → 4 канонических ресурса →
  5 коррелированных рисков, снижение шума 69 %;
- таблица правил корреляции `ASCC-CHAIN-001/002/003`, `ASCC-CORR-010`;
- known limitation: SG и присоединённый к нему инстанс остаются раздельными
  ресурсами (edge-модели пока нет) — это ограничение фикстуры **сохраняют**
  (SG и EC2-инстанс не объединены в один идентификатор).

Конкретные значения полей (ARN, ID находок, CVE, описания) — синтетические
данные фикстуры, а не цитаты из RUNBOOK. Структура JSON (имена и вложенность
полей) соответствует реальным форматам вывода Trivy JSON, Prowler OCSF JSON
и Checkov JSON.

## Сценарий

Один AWS-аккаунт (`123456789012`, `us-east-1`), четыре связанных ресурса:

| Ресурс | Terraform-адрес | Идентификатор в облаке |
|---|---|---|
| S3-бакет с сырыми данными | `aws_s3_bucket.datalake_raw` | `arn:aws:s3:::datalake-raw` |
| EC2 ETL-хост | `aws_instance.datalake_etl` | `arn:aws:ec2:us-east-1:123456789012:instance/i-0a1b2c3d4e5f67890` |
| IAM-роль ETL-хоста | `aws_iam_role.datalake_etl_role` | `arn:aws:iam::123456789012:role/datalake-etl-role` |
| Security Group ETL-хоста | `aws_security_group.datalake_etl_sg` | `arn:aws:ec2:us-east-1:123456789012:security-group/sg-0f9e8d7c6b5a43210` |

Цепочка: security group открывает `0.0.0.0/0` на порт 22 → EC2-инстанс
`datalake-etl` публично доступен и несёт критическую RCE-уязвимость
(Log4Shell, CVE-2021-44228) → к инстансу привязана IAM-роль
`datalake-etl-role` с inline-политикой `Action:* / Resource:*` →
эта роль имеет доступ к S3-бакету `datalake-raw`, который публично
читаем, не зашифрован, без логирования и помечен тегом
`DataClassification=PII`.

## Кто что видит

| Ресурс | Trivy | Prowler | Checkov |
|---|---|---|---|
| S3 bucket `datalake-raw` | misconfig: нет шифрования (`AVD-AWS-0028`) | 3 находки: public access, no encryption, no logging | 3 находки: `CKV_AWS_20`, `CKV_AWS_19`, `CKV_AWS_18` |
| EC2 `datalake-etl` | 4 CVE в установленных пакетах, включая CRITICAL Log4Shell | 1 находка: публичный IP | — |
| IAM-роль `datalake-etl-role` | — | 1 находка: full admin inline policy | 1 находка: `CKV_AWS_40` |
| SG `datalake-etl-sg` | misconfig: ingress 0.0.0.0/0:22 (`AVD-AWS-0107`) | 1 находка: SSH open to internet | — |

Итого: Trivy — 6 находок (4 vuln + 2 misconfig), Prowler — 6, Checkov — 4.
**16 сырых находок, 3 инструмента** — совпадает с метрикой из RUNBOOK.
Каждый из 4 ресурсов виден минимум двум инструментам под разными
идентификаторами (ARN vs Terraform-адрес vs bucket/role/instance name) —
это и есть материал для identity resolution.

## Какую корреляцию это должно выявить

- **`ASCC-CHAIN-001`** (public + unencrypted + PII-tagged store, logging off) —
  срабатывает только на бакете `datalake-raw`, объединяя теги Prowler
  (`DataClassification=PII`) с IaC-находками Checkov/Trivy (encryption,
  public ACL, logging).
- **`ASCC-CHAIN-002`** (internet-reachable host с critical CVE) — SG-находка
  (Trivy `AVD-AWS-0107` + Prowler `ec2_securitygroup_...port_22`) соединяется
  с Log4Shell на инстансе `datalake-etl` (Trivy vuln-скан).
- **`ASCC-CHAIN-003`** (internet → vulnerable host → over-privileged role →
  sensitive data) — полная цепочка через все 4 ресурса и все 3 инструмента:
  SG → EC2 (CVE) → IAM-роль (Prowler + Checkov) → S3-бакет.
- **`ASCC-CORR-010`** (≥2 независимых инструмента согласны по одной
  категории) — минимум дважды: по бакету (Prowler + Checkov + Trivy сходятся
  на «нет шифрования») и по SG (Trivy + Prowler сходятся на «SSH открыт
  в интернет»).

Итого ожидается **5 коррелированных рисков** из **4 канонических ресурсов** —
те же числа, что в таблице метрик RUNBOOK.md. Это ожидание от данных
фикстуры, а не факт: сама логика корреляции (`src/ascc/correlate/`) пока не
реализована — команда `ascc correlate` печатает заглушку `TODO: correlation
logic`, эти фикстуры лишь дают ей материал для будущей реализации и тестов.

## Намеренно нескоррелированное

Security Group и присоединённый к ней EC2-инстанс — раздельные ресурсы
(EC2 `data.security_groups` содержит SG id, но обратного edge не строится).
Это осознанно воспроизводит known limitation из RUNBOOK: «Prowler blames
the instance, Checkov blames the SG, so the SSH finding does not corroborate»
— в этой фикстуре аналогично нет built-in edge между SG и инстансом, только
сырые данные, которые *позволяют* его построить, когда edge-модель появится.
