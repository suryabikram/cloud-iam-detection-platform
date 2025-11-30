def alert(message, event=None):
    print(f"\n[ALERT] {message}")
    if event:
        print(f"  Event:      {event.get('eventName')}")
        print(f"  User:       {event.get('user')}")
        print(f"  Source IP:  {event.get('sourceIPAddress')}")
        print(f"  Region:     {event.get('awsRegion')}")