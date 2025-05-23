FROM openjdk:11

ARG SOURCE
ARG COMMIT_HASH
ARG COMMIT_ID
ARG BUILD_TIME
LABEL source=${SOURCE}
LABEL commit_hash=${COMMIT_HASH}
LABEL commit_id=${COMMIT_ID}
LABEL build_time=${BUILD_TIME}

# can be passed during Docker build as build time environment for github branch to pickup configuration from.
ARG container_user=mosip

# can be passed during Docker build as build time environment for github branch to pickup configuration from.
ARG container_user_group=mosip

# can be passed during Docker build as build time environment for github branch to pickup configuration from.
ARG container_user_uid=1001

# can be passed during Docker build as build time environment for github branch to pickup configuration from.
ARG container_user_gid=1001

ARG KUBECTL_VERSION=1.22.9

WORKDIR /home/${container_user}

ENV work_dir=/home/${container_user}

COPY ./api-test/target $work_dir/
COPY application.properties $work_dir/
COPY ["Biometric Devices", "$work_dir/Biometric Devices"]
COPY ["resource", "$work_dir/resource"]
COPY entrypoint.sh $work_dir

RUN apt-get -y update && \
    apt-get install -y unzip jq && \
    groupadd -g ${container_user_gid} ${container_user_group} && \
    useradd -u ${container_user_uid} -g ${container_user_group} -s /bin/sh -m ${container_user} && \
    curl -LO "https://storage.googleapis.com/kubernetes-release/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl" && \
    chmod +x kubectl && \
    mv kubectl /usr/local/bin/ && \
    chown -R ${container_user}:${container_user} /home/${container_user} /usr/local/openjdk-11/lib/security/cacerts && \
    chmod 644 /usr/local/openjdk-11/lib/security/cacerts && \
    chmod +x $work_dir/entrypoint.sh


USER ${container_user_uid}:${container_user_gid}

WORKDIR ${work_dir}

EXPOSE 8083

ENV MODULES=
ENV ENV_USER=
ENV ENV_ENDPOINT=
ENV ENV_TESTLEVEL=smokeAndRegression

ENTRYPOINT ["./entrypoint.sh"]