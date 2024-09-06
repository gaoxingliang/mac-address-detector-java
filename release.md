# how to release to maven central
some envs are stored in local ~/.zshrc
```shell
export JRELEASER_GPG_PASSPHRASE=
export JRELEASER_GITHUB_TOKEN=
export JRELEASER_DEPLOY_MAVEN_MAVENCENTRAL_SONATYPE_USERNAME=
export JRELEASER_DEPLOY_MAVEN_MAVENCENTRAL_SONATYPE_PASSWORD=
```

gpg files are stored in local vm.
```shell
        publicKey = '/Users/edward/.jreleaser/public.pgp'
        secretKey = '/Users/edward/.jreleaser/private.pgp'
```

Now it's manually uploaded by guide [here](https://central.sonatype.org/publish/publish-portal-upload/#switching-to-ossrh-during-portal-early-access).
So the commands are:<br>
```shell
./gradlew clean
./gradlew publish
./gradlew jreleaserFullRelease
# upload this bundle zip:
ls ./build/jreleaser/deploy/mavenCentral/sonatype
```
<br>


It should use gradle command by guide [here](https://jreleaser.org/guide/latest/examples/maven/maven-central.html#_gradle)