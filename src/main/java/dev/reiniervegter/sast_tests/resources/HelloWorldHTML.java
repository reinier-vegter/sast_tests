package dev.reiniervegter.sast_tests.resources;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Locale;

@Controller
public class HelloWorldHTML {
    // XSS: NOT PICKED UP
    @RequestMapping(value = "/helloHtml", method = RequestMethod.GET)
    public String home(Locale locale, Model model, @RequestParam(value="name", defaultValue="World") String name) {
        model.addAttribute("body", new HelloWorld.FooObject(name));
        return "foo";
    }

    // NOT XSS: NOT PICKED UP (OK)
    @RequestMapping(value = "/helloHtmlSafe", method = RequestMethod.GET)
    public String homeSafe(Locale locale, Model model, @RequestParam(value="name", defaultValue="World") String name) {
        model.addAttribute("body", new HelloWorld.FooObject(name));
        return "bar";
    }
}
