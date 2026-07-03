#!/bin/sh
docker run -ti -v $(pwd):/home/app rust:bookworm /bin/sh -c "cd /home/app && apt install git && cargo build --release"
