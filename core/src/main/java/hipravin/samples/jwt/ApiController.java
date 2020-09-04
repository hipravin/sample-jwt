package hipravin.samples.jwt;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api/v1")
public class ApiController {

    @GetMapping("/public/test")
    ResponseEntity<String> publicTest() {
        return ResponseEntity.ok("Hey buddy");
    }

    @GetMapping("/secure/test")
    ResponseEntity<String> secureTest(Principal principal) {
        return ResponseEntity.ok("Hey secured buddy, " + principal.getName());
    }

    @GetMapping("/secure//admin/test")
    ResponseEntity<String> secureAdminTest(Principal principal) {
        return ResponseEntity.ok("Hey secured buddy admin, " + principal.getName());
    }
}
