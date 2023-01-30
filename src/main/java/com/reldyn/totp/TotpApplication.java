package com.reldyn.totp;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.CodeGenerationException;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import jakarta.annotation.PostConstruct;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class TotpApplication {

    public static void main(String[] args) {
        SpringApplication.run(TotpApplication.class, args);
    }

    @PostConstruct
    public void generateTotp() throws CodeGenerationException, InterruptedException {
        SecretGenerator secretGenerator = new DefaultSecretGenerator(64);
        String secret = secretGenerator.generate();
        System.out.println("Secret: " + secret);

        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA512, 6);

        DefaultCodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
        // sets the time period for codes to be valid for to 5 seconds
        verifier.setTimePeriod(5);

		// allow codes valid for 2 time periods before/after to pass as valid
        verifier.setAllowedTimePeriodDiscrepancy(1);

        // generate new code every 5 seconds
        long key =Math.floorDiv(timeProvider.getTime(), 5);
        String code = codeGenerator.generate(secret, key);
		System.out.println("Key: " + key + ", Code: " + code);

		long t= System.currentTimeMillis();
		long end = t+15000;
		while(System.currentTimeMillis() < end) {
			System.out.println("----- Verify now -----");

			long verifyKey =Math.floorDiv(timeProvider.getTime(), 5);
			String verifyCode = codeGenerator.generate(secret, verifyKey);
			System.out.println("Key: " + verifyKey + ", Code: " + verifyCode);
			System.out.println("Result: " + verifier.isValidCode(secret, code));
			System.out.println("Sleep 2 seconds");
			Thread.sleep( 2000 );
		}
    }

}
