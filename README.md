/me playing with Auth0


# Run

## Server

    cd server/
    pipenv install
    API_AUDIENCE="http://minimal-demo-iam.localhost:8000" pipenv run python server.py

## UI

    cd ui/
    python3 -m http.server 3000
