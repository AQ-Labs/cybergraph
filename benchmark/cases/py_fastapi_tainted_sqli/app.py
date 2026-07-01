@app.get("/search")
def search(request):
    q = request.query["q"]
    return db.execute("select * from users where name = " + q)
