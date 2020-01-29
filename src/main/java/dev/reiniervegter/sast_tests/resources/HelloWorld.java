package dev.reiniervegter.sast_tests.resources;

import com.reinier.Encodable;
import org.owasp.encoder.Encode;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.reinier.CrapEncoding;

@RestController
public class HelloWorld {
    // XSS: Found
    @RequestMapping("/greetingSingle")
    public ResponseEntity greetingSingle(@RequestParam(value="name", defaultValue="World") String name) {
        return new ResponseEntity("Hi: " + name, HttpStatus.OK);
    }

    // XSS: Found
    @RequestMapping("/greetingConcat")
    public ResponseEntity greetingConcat(@RequestParam(value="name", defaultValue="World") String name) {
        return new ResponseEntity(this.foo(name), HttpStatus.OK);
    }

    // XSS: Found
    @RequestMapping("/greetingSb")
    public ResponseEntity greetingSb(@RequestParam(value="name", defaultValue="World") String name) {
        return new ResponseEntity(this.bar(name), HttpStatus.OK);
    }

    // XSS: Found
    @RequestMapping("/greetingObjectAsString")
    public String greetingObjectAsString(@RequestParam(value="name", defaultValue="World") String name) {
        return String.valueOf(new FooObject(name));
    }

    // NOT XSS. Found, false positive in all types of scanning
    @RequestMapping("/greetingObject")
    public ResponseEntity greetingObject(@RequestParam(value="name", defaultValue="World") String name) {
        return new ResponseEntity(new FooObject(name), HttpStatus.OK);
    }

    // NOT XSS, not marked as such (OK)
    @RequestMapping("/greetingObjectAsDependencyEncodedString")
    public String greetingObjectAsDependencyEncodedString(@RequestParam(value="name", defaultValue="World") String name) {
        return Encode.forHtml(new FooObject(name).getOut());
    }

    // RESULT: NOT PICKED UP
    @RequestMapping("/greetingObjectAsFaultyEncodedString")
    public String greetingObjectAsFaultyEncodedString(@RequestParam(value="name", defaultValue="World") String name) {
        return crapLocalEncoding(new FooObject(name).getOut());
    }

    // XSS: Found
    @RequestMapping("/greetingObjectDependencyCrapEncoding")
    public String greetingObjectDependencyCrapEncoding(@RequestParam(value="name", defaultValue="World") String name) {
        return new CrapEncoding().encode(new FooObject(name).getOut());
    }

    // XSS: Found. How is this being found without a build ??
    @RequestMapping("/greetingObjectDependencyCrapEncodingIndirect")
    public String greetingObjectDependencyCrapEncodingIndirect(@RequestParam(value="name", defaultValue="World") String name) {
        return new CrapEncoding().autoGetEncoded(new FooObject(name));
    }

    // <> replaced. Not hidden for scanner (replaceAll), so it works based on assumption ?!
    @RequestMapping("/greetingObjectDependencyCrapEncodingProperlyIsh")
    public String greetingObjectDependencyCrapEncodingProperlyIsh(@RequestParam(value="name", defaultValue="World") String name) {
        return new CrapEncoding().encodeProperlyIsh(new FooObject(name).getOut());
    }

    // Found in case of cloud scan (zip), but not in a local scan.
    // It's not vulnerable since it's not called by anything.
    // Probably triggered by '@RequestParam'.
    public ResponseEntity danglingMethodWithAnnotation(@RequestParam(value="name", defaultValue="World") String name) {
        return new ResponseEntity(this.bar(name), HttpStatus.OK);
    }

    public ResponseEntity danglingMethod(String name) {
        return new ResponseEntity(this.bar(name), HttpStatus.OK);
    }

    private String foo(String in) {
        return "this is " + in;
    }

    private String bar(String in) {
        return new StringBuilder()
                .append("this is")
                .append(in).toString();
    }

    private String crapLocalEncoding(String in) {
        return in.replaceAll("[U]", "X"); // This hides an XSS sink
    }

    public static class FooObject implements Encodable {
        public String in;
        public String out;
        public FooObject(String in) {
            this.in = in;
            this.out = this.toString();
        }

        public String getOut() {
            return this.out;
        }

        public String getData() {
            return in;
        }

        // Yes, weirdness...
        public String setData() {
            return in;
        }

        @Override
        public String toString() {
            return "this is " + this.in;
        }
    }
}
