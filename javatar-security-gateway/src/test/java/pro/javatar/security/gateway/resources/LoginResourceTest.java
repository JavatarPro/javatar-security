package pro.javatar.security.gateway.resources;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.PropertySource;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Borys Zora
 * @version 2019-06-01
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {
        SpringTestConfig.class //,
        //LoginResourceTest.SpringConfig.class
})
@PropertySource("classpath:application.yml")
@WebAppConfiguration
class LoginResourceTest {

    @Autowired
    LoginResource loginResource;

    MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        this.mockMvc = MockMvcBuilders
                .standaloneSetup(this.loginResource)
                .setMessageConverters(new MappingJackson2HttpMessageConverter()) // Important!
                .build();
    }

    @Test
    void login() throws Exception {
        mockMvc.perform(post("/login")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(getStub("gateway/login-request.json")))
                .andDo(print()).andExpect(status().isUnauthorized()).andReturn();
    }

    private String getStub(String classpathFile) throws Exception {
        return new String(Files.readAllBytes(Paths.get(getClass().getClassLoader().getResource(classpathFile).toURI())));
    }

//    @ComponentScan("pro.javatar.security.gateway")
//    public static class SpringConfig {
//    }

}