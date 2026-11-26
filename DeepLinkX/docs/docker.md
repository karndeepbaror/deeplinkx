# Docker

```bash
export DEEPLINKX_API_TOKEN=$(openssl rand -hex 16)
docker compose up --build            # dashboard + API on http://127.0.0.1:8787
docker run --rm -v "$PWD:/work" deeplinkx:1.0.0 scan app.apk -p ci -f sarif,html -o reports
```

The image runs as a non-root user, keeps history in the `/data` volume and ships `adb`. The compose file drops all capabilities and mounts the root filesystem read-only.
For dynamic testing from a container, run an adb server on the host (`adb -a nodaemon server`) and pass `-e ADB_SERVER_SOCKET=tcp:host.docker.internal:5037`; keep the emulator isolated from anything sensitive.
