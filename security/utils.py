from user_agents import parse


def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


def get_device_info(request):
    user_agent_str = request.META.get("HTTP_USER_AGENT", "")
    user_agent = parse(user_agent_str)

    return {
        "browser": f"{user_agent.browser.family} {user_agent.browser.version_string}",
        "os": f"{user_agent.os.family} {user_agent.os.version_string}",
        "device_type": "Mobile" if user_agent.is_mobile else "Tablet" if user_agent.is_tablet else "PC",
    }
