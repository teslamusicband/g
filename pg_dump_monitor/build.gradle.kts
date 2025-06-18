plugins {
    `maven-publish`
    java
}

publishing {
    repositories {
        maven {
            url = uri(System.getProperty("nexusUrl"))
            credentials {
                username = System.getProperty("nexusUsername")
                password = System.getProperty("nexusPassword")
            }
        }
    }
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
        }
    }
}
