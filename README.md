# HelloWorld app

Bunch of different paths to XSS, to see how SAST behaves:
direct, indirect, through transitive dependencies, through template engine etc.

# Build

Run `mvn clean package`.

Find the .jar-file in `target/`.

Run with `java -jar target/....jar`.

# Run locally with maven

Run `mvn spring-boot:run`

Visit `http://localhost:8080/greeting?name=foo`.
