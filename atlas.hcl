// Atlas project configuration, per ADR-GLB-004.
//
// Every environment scopes Atlas to the `identity` schema. That scope is load-bearing:
// the same database also carries the `platform` schema, which foundation-platform owns
// and ships as versioned SQL. Unscoped, Atlas would read `platform` as drift against
// schema.hcl and plan to drop it.

variable "url" {
  type    = string
  default = getenv("DATABASE_URL")
}

// Atlas computes a diff by materialising the desired state on a throwaway database. It
// must be a real PostgreSQL of the same major version the schema is deployed against —
// a version mismatch here produces a plan that is correct for the wrong server.
variable "dev_url" {
  type    = string
  default = getenv("ATLAS_DEV_URL")
}

env "local" {
  src     = "file://schema.hcl"
  url     = var.url
  dev     = var.dev_url
  schemas = ["identity"]

  migration {
    dir = "file://migrations"

    // Atlas's own bookkeeping lives outside the schema it manages.
    //
    // Without this it lands in `identity`, and `grants.sql` grants the runtime role DML on
    // every table in that schema — so the runtime could rewrite migration history, and a
    // later `atlas migrate apply` would re-run or skip migrations based on rows the
    // application was able to change. Found by running the pipeline and querying
    // has_table_privilege, not by reading the configuration.
    revisions_schema = "atlas"
  }

  format {
    migrate {
      diff = "{{ sql . \"  \" }}"
    }
  }
}

env "ci" {
  src     = "file://schema.hcl"
  url     = var.url
  dev     = var.dev_url
  schemas = ["identity"]

  migration {
    dir = "file://migrations"

    // Atlas's own bookkeeping lives outside the schema it manages.
    //
    // Without this it lands in `identity`, and `grants.sql` grants the runtime role DML on
    // every table in that schema — so the runtime could rewrite migration history, and a
    // later `atlas migrate apply` would re-run or skip migrations based on rows the
    // application was able to change. Found by running the pipeline and querying
    // has_table_privilege, not by reading the configuration.
    revisions_schema = "atlas"
  }

  // `atlas migrate lint`, the plan analyzer of ADR-GLB-004 §5.1 item 4. Since Atlas v0.38 it runs
  // only with an Atlas Pro login: "Starting with v0.38, the atlas migrate lint command is available
  // only to Atlas Pro users." This block is inert until such a login exists, and kept so the
  // configuration is ready then.
  //
  // The gate does not wait for it. ci.yml runs items 1 to 3 of §5.1: `atlas migrate validate`, the
  // destructive-statement gate (squawk over the new migrations, .squawk.toml) and the synchronisation
  // check. "A pipeline that implements items 1 and 2 meets this gate. It is not a waiver"
  // (ADR-GLB-004, amended 2026-10-20).
  lint {
    destructive {
      error = true
    }
    incompatible {
      error = true
    }
  }
}
