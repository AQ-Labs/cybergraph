package demo;

import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {

    @GetMapping("/users")
    public String listUsers(@RequestParam String name) {
        return statement.executeQuery("select * from users where name = '" + name + "'");
    }
}
