from fastapi import FastAPI

app = FastAPI()


def read_file(name):
    with open("/data/" + name) as handle:
        return handle.read()


@app.get("/file")
def get_file(name: str):
    return read_file(name)
