{
  description = "Mint swap tracker";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        postgresPort = 5432;
      in {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            pkg-config
            openssl
          ];

          shellHook = ''
            export PGHOST="''${PGHOST:-127.0.0.1}"
            export PGPORT="${toString postgresPort}"

            export PGADMIN_USER="''${PGADMIN_USER:-postgres}"
            export PGADMIN_DB="''${PGADMIN_DB:-postgres}"

            export APP_DB_NAME="''${APP_DB_NAME:-mint_swap_tracker}"
            export APP_DB_OWNER="''${APP_DB_OWNER:-mint_swap_app}"
            export APP_DB_PASSWORD="''${APP_DB_PASSWORD:-mint_swap_app_password}"

            export DATABASE_URL="postgresql://$APP_DB_OWNER:$APP_DB_PASSWORD@$PGHOST:$PGPORT/$APP_DB_NAME"

            reset_db() {
              echo "ensuring role $APP_DB_OWNER exists with configured password..."
              psql -h "$PGHOST" -p "$PGPORT" -U "$PGADMIN_USER" -d "$PGADMIN_DB" <<EOFSQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$APP_DB_OWNER') THEN
    CREATE ROLE "$APP_DB_OWNER" WITH LOGIN PASSWORD '$APP_DB_PASSWORD';
  ELSE
    ALTER ROLE "$APP_DB_OWNER" WITH LOGIN PASSWORD '$APP_DB_PASSWORD';
  END IF;
END
\$\$;
EOFSQL

              echo "terminating active sessions on $APP_DB_NAME..."
              psql -h "$PGHOST" -p "$PGPORT" -U "$PGADMIN_USER" -d "$PGADMIN_DB" -c \
                "SELECT pg_terminate_backend(pid)
                 FROM pg_stat_activity
                 WHERE datname = '$APP_DB_NAME' AND pid <> pg_backend_pid();" >/dev/null || true

              echo "dropping database $APP_DB_NAME if it exists..."
              dropdb --if-exists -h "$PGHOST" -p "$PGPORT" -U "$PGADMIN_USER" "$APP_DB_NAME"

              echo "creating database $APP_DB_NAME owned by $APP_DB_OWNER..."
              createdb -h "$PGHOST" -p "$PGPORT" -U "$PGADMIN_USER" -O "$APP_DB_OWNER" "$APP_DB_NAME"

              echo "applying schema sql/schema.sql..."
              PGPASSWORD="$APP_DB_PASSWORD" \
              psql -h "$PGHOST" -p "$PGPORT" -U "$APP_DB_OWNER" -d "$APP_DB_NAME" -f sql/schema.sql

              echo "database reset complete"
            }

            alias pg-start='echo "using system postgres at $PGHOST:$PGPORT"'
            alias pg-stop='echo "not stopping system postgres from dev shell"'
            alias pg-reset='reset_db'
            alias psql-admin='psql -h "$PGHOST" -p "$PGPORT" -U "$PGADMIN_USER" -d "$PGADMIN_DB"'
            alias psql-local='PGPASSWORD="$APP_DB_PASSWORD" psql -h "$PGHOST" -p "$PGPORT" -U "$APP_DB_OWNER" -d "$APP_DB_NAME"'
            alias cargo-run='cargo run --release -- --config config.toml'
            alias cargo-check-db='DATABASE_URL="$DATABASE_URL" cargo check'

            echo "Using system postgres at $PGHOST:$PGPORT"
            echo "Admin user:    $PGADMIN_USER"
            echo "App DB:        $APP_DB_NAME"
            echo "App owner:     $APP_DB_OWNER"
            echo "Run 'pg-reset' to drop, recreate, and load schema."
            echo "DATABASE_URL=$DATABASE_URL"
          '';
        };
      });
}
