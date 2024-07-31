

agent_id = "001"

dest_socket = "/var/ossec/queue/sockets/wmodules"

        # Simple socket message
msg = f"{str(agent_id).zfill(3)} {component} {GETCONFIG_COMMAND} {configuration}"