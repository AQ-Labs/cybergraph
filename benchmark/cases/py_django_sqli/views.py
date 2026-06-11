def list_users(request):
    name = request.GET["q"]
    return User.objects.raw("select * from users where name = '" + name + "'")
