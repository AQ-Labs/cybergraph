from fastapi import FastAPI, Request

app = FastAPI()


def raw_sql(query: str):
    return db.execute(query)


@app.get("/users")
def list_users(request: Request):
    name = request.query_params["name"]
    return raw_sql("select * from users where name = '" + name + "'")
