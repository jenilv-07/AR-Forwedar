from ar_send import AR_send,WazuhInternalError



# path of socket
path = "/var/ossec/queue/alerts/ar"


ar_conneciotn = AR_send(path=path)

msg = '(msg_to_agent) [] NNS 001 {"version": 1, "origin": {"name": null, "module": "API"}, "command": "quick-scan0", "parameters": {"extra_args": [], "alert": {"data": {}}}}'

encode_msg = msg.encode()

ar_conneciotn.send(encode_msg)