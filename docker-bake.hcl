# Diatreme sets these for a release: VERSION (pr-<N> on a pull request, the release tag
# after a merge), REGISTRY and IMAGE_NAME (<owner>/<repository>).
variable "VERSION" { default = "latest" }
variable "REGISTRY" { default = "ghcr.io" }
variable "IMAGE_NAME" { default = "magmamoose/secrets-ui" }
variable "PLATFORMS" { default = "linux/amd64,linux/arm64" }

group "default" {
  targets = ["app"]
}

target "app" {
  context    = "."
  dockerfile = "Dockerfile"
  platforms  = split(",", PLATFORMS)
  tags       = ["${REGISTRY}/${IMAGE_NAME}:${VERSION}"]
  args = {
    VERSION = "${VERSION}"
  }
  labels = {
    "org.opencontainers.image.source"      = "https://github.com/MagmaMoose/secrets-ui"
    "org.opencontainers.image.description" = "Manage secrets in the browser, signed in with Entra ID or Google and acting as yourself"
    "org.opencontainers.image.licenses"    = "Apache-2.0"
  }
}

# Local single-arch build that loads into Docker: docker buildx bake app-local
target "app-local" {
  inherits  = ["app"]
  platforms = []
  tags      = ["secrets-ui:dev"]
  output    = ["type=docker"]
}
