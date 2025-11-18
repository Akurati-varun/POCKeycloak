FROM quay.io/keycloak/keycloak:26.4.2

# Build Keycloak with the optimized build option
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true
ENV KC_DB=postgres
ENV KC_FEATURES=token-exchange

WORKDIR /opt/keycloak

RUN /opt/keycloak/bin/kc.sh build --features=token-exchange

# Expose the default HTTP port
EXPOSE 8080

ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start", "--optimized"]
