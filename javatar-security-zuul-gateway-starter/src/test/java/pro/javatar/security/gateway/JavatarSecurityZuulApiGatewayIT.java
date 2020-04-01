package pro.javatar.security.gateway;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@ContextConfiguration
//@ActiveProfiles("component-test")
class JavatarSecurityZuulApiGatewayIT {

	@Test
	void contextLoads() {
	}

}
