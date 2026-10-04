ARG PG=17
FROM postgres:${PG}
ARG PG=17
RUN apt-get update -qq && apt-get install -y -qq postgresql-plpython3-${PG} postgresql-plperl-${PG} \
      postgresql-${PG}-http postgresql-${PG}-pg-background \
      postgresql-server-dev-${PG} libcurl4-openssl-dev libicu-dev build-essential curl ca-certificates >/dev/null \
 && curl -sL https://github.com/supabase/pg_net/archive/refs/heads/master.tar.gz | tar xz -C /tmp \
 && cd /tmp/pg_net-master && make -s && make -s install \
 && rm -rf /var/lib/apt/lists/*
