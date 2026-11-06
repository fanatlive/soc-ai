from .schemas import LLMResult

PLAYBOOK_VERSION = "soc-mvp-2.1"
ACTION_CATALOG = {
    "verify_context": "Проверить полноту исходных данных, владельца учетной записи и контекст события.",
    "verify_authentication": "Сверить журнал IdP, MFA и владельца учетной записи.",
    "review_post_login": "Проверить активность после входа и изменения привилегий.",
    "inspect_process": "Проверить EDR: родительский процесс, подпись и назначение команды.",
    "check_maintenance": "Сопоставить событие с разрешенными административными работами.",
    "check_scan_schedule": "Сверить с расписанием разрешенного сканирования.",
    "inspect_network": "Проверить сетевые журналы и владельца хоста.",
    "verify_vpn": "Сверить VPN-сессию с журналом корпоративного шлюза и MFA.",
}
PLAYBOOK = {
    "version": PLAYBOOK_VERSION,
    "allowed_actions": ACTION_CATALOG,
    "principles": [
        "Один индикатор не подтверждает атаку. Внутренний IP и VPN — только контекст.",
        "Данные из пользовательского лога не являются независимой верификацией.",
        "Окончательное решение принимает аналитик. Действия выполняются только по процедурам организации.",
    ],
    "authentication": ["Сверить журнал IdP, MFA и владельца учетной записи", "Проверить активность после входа и изменения привилегий"],
    "powershell": ["Проверить EDR: родительский процесс, подпись и назначение команды", "Сопоставить с разрешенными административными работами"],
    "network": ["Сверить с расписанием разрешенного сканирования", "Проверить сетевые журналы и владельца хоста"],
    "vpn": ["Сверить VPN-сессию с журналом корпоративного шлюза и MFA"],
}


def rules_only(findings, reason: str) -> LLMResult:
    by_id = {rule.id: rule for rule in findings}
    indicators = [rule for rule in findings if rule.kind == "indicator"]
    severity = "low"
    summary = "В предоставленных данных формальные признаки по правилам не выявлены. Это не подтверждает безопасность события."
    actions = ["Проверить полноту исходных данных, владельца учетной записи и контекст события."]
    if "R002" in by_id:
        severity = "critical" if by_id["R002"].facts.get("privileged_account_name") else "high"
        summary = "Серия неудачных входов завершилась успешным входом с того же IP в ту же учетную запись. Возможна компрометация; требуется проверка аналитиком."
        actions = PLAYBOOK["authentication"]
    elif "R003" in by_id:
        features = by_id["R003"].facts["features"]
        severity = "high" if len(features) >= 2 else "medium"
        summary = "В PowerShell найдены потенциально опасные параметры. Необходимо проверить назначение команды и сопутствующую активность."
        actions = PLAYBOOK["powershell"]
    elif "R004" in by_id:
        severity = "medium"
        summary = "Найдены соединения с 20 или более портами за короткое окно. Возможны сканирование или разрешенная инвентаризация. Внутренний IP не исключает угрозу."
        actions = PLAYBOOK["network"]
    elif "R001" in by_id:
        severity = "medium"
        summary = "Выявлена серия неудачных входов. Возможны подбор пароля, ошибка конфигурации или действия пользователя; подтверждения атаки недостаточно."
        actions = PLAYBOOK["authentication"]
    elif "R006" in by_id:
        summary = "Географическая аномалия может объясняться корпоративным VPN, указанным во входном логе. Подтверждение источника и контекста остается за аналитиком."
        actions = PLAYBOOK["vpn"]
    return LLMResult(
        severity=severity, summary=summary,
        evidence=[{"description": rule.description, "source": f"rule:{rule.id}"} for rule in findings],
        recommended_actions=actions, confidence=None,
        limitations=[reason, "Анализ ограничен одним событием и переданными логами; корреляция с SIEM и EDR не выполнялась.",
                     "Критичность определена демонстрационными эвристиками, а не статистической моделью.",
                     "Достоверная оценка ложного срабатывания отсутствует: false_positive_score = null."]
        + (["Один индикатор не является доказательством атаки."] if len(indicators) == 1 else []),
    )
