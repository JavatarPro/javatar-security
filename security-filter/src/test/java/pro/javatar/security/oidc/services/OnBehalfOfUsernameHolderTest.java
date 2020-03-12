package pro.javatar.security.oidc.services;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.nullValue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pro.javatar.security.oidc.model.UserKey;

class OnBehalfOfUsernameHolderTest {

    private OnBehalfOfUsernameHolder holder;

    @BeforeEach
    void setUp() {
        holder = new OnBehalfOfUsernameHolder();
    }

    @Test
    void checkHoldingUserKeyBetweenThreads() throws Exception {
        assertThat(holder.getUser(), is(nullValue()));
        UserKey userKey1 = new UserKey("user1", "realm1");
        holder.putUser(userKey1);
        assertThat(holder.getUser(), is(userKey1));

        //replace current user key
        holder.putUser("user2", "realm2");
        UserKey userKey2 = new UserKey("user2", "realm2");
        assertThat(holder.getUser(), is(userKey2));

        //set user key from another thread
        Thread thread = new Thread(() -> {
            UserKey userKey3 = new UserKey("user3", "realm3");
            holder.putUser(userKey3);
            assertThat(holder.getUser(), is(userKey3));
        });

        thread.start();
        Thread.sleep(2000);

        assertThat(holder.getUser(), is(userKey2));
    }

    @Test
    void putWrongUserKey() {
        holder.putUser("", "ream1");
        assertThat(holder.getUser(), is(nullValue()));

        holder.putUser(null, "ream1");
        assertThat(holder.getUser(), is(nullValue()));

        holder.putUser("userlogin", "");
        assertThat(holder.getUser(), is(nullValue()));

        holder.putUser("userlogin", null);
        assertThat(holder.getUser(), is(nullValue()));
    }

    @Test
    void removeUserKey() {
        assertThat(holder.getUser(), is(nullValue()));
        UserKey userKey1 = new UserKey("user1", "realm1");
        holder.putUser(userKey1);
        assertThat(holder.getUser(), is(userKey1));

        holder.removeUser();
        assertThat(holder.getUser(), is(nullValue()));
    }
}