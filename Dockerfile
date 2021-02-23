FROM ubuntu:latest
RUN apt-get update && apt-get install -y python3 python3-pip
RUN pip3 install pipenv
COPY entrypoint.sh /entrypoint.sh
COPY gh2jira *.py Pipfile /
RUN cd / && PIPENV_VENV_IN_PROJECT=1 pipenv install
ENTRYPOINT ["/entrypoint.sh"]
