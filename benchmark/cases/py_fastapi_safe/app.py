from fastapi import FastAPI, Request

app = FastAPI()


@app.get("/health")
def health(request: Request):
    # No sink: returns a constant. A secure baseline case.
    return {"status": "ok"}


@app.get("/echo")
def echo(request: Request):
    name = request.query_params["name"]
    return {"name": name.strip()}
