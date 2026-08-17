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
  }

  // ADR-GLB-004 requires the pipeline to block a destructive plan rather than report it,
  // and names `atlas migrate lint` as the mechanism. Since Atlas v0.38 that command aborts
  // on the free CLI: "'atlas migrate lint' is available only to Atlas Pro users."
  //
  // This block is therefore inert today. It is kept rather than deleted because it is
  // correct the moment an Atlas Pro login exists, and deleting it would erase the record
  // that the mandated configuration was written. ci.yml runs `atlas migrate validate`,
  // which is free and checks directory integrity, plus a text-level destructive gate that
  // stands in for the analyzer. That substitution is recorded as debt in ROADMAP.md.
  lint {
    destructive {
      error = true
    }
    incompatible {
      error = true
    }
  }
}
