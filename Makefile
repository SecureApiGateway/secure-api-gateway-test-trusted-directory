name := secure-api-gateway-test-trusted-directory
repo := europe-west4-docker.pkg.dev/sbat-gcr-develop/sapig-docker-artifact
service := sapig-test-trusted-directory
helm_repo := forgerock-helm/secure-api-gateway/${name}/

docker: build-java copy-java-dependencies conf
ifndef tag
	$(warning no tag supplied; latest assumed)
	$(eval TAG=latest)
else
	$(eval TAG=$(shell echo $(tag) | tr A-Z a-z))
endif
ifndef setlatest
	$(warning no setlatest true|false supplied; false assumed)
	$(eval setlatest=false)
endif
	@if [ "${setlatest}" = "true" ]; then \
		docker build secure-api-gateway-test-trusted-directory-docker -t ${repo}/securebanking/${service}:${TAG} -t ${repo}/securebanking/${service}:latest; \
		docker push ${repo}/securebanking/${service} --all-tags; \
    else \
   		docker build secure-api-gateway-test-trusted-directory-docker -t ${repo}/securebanking/${service}:${TAG}; \
   		docker push ${repo}/securebanking/${service}:${TAG}; \
   	fi;
conf:
ifndef env
	$(warning no env supplied; prod assumed)
	$(eval env=prod)
endif
	@if [ "${env}" = "prod" ]; then \
  		IG_MODE="production"; \
  	else \
  		IG_MODE="development"; \
  	fi; \
	echo "init config for env: ${env}, igmode: $$IG_MODE\n"; \
	./bin/config.sh init --env ${env} --igmode $${IG_MODE}

build-java:
	mvn -U install

copy-java-dependencies:
	mvn -U dependency:copy-dependencies --projects secure-api-gateway-test-trusted-directory-docker -DoutputDirectory=./7.3.0/ig/lib

clean:
	mvn clean
	./bin/config.sh clean
	rm -rf secure-api-gateway-test-trusted-directory-docker/7.3.0/ig/lib

package_helm:
ifndef version
	$(error A version must be supplied, Eg. make helm version=1.0.0)
endif
	helm dependency update _infra/helm/${name}
	helm template _infra/helm/${name}
	helm package _infra/helm/${name} --version ${version} --app-version ${version}

publish_helm:
ifndef version
	$(error A version must be supplied, Eg. make helm version=1.0.0)
endif
	jf rt upload  ./*-${version}.tgz ${helm_repo}