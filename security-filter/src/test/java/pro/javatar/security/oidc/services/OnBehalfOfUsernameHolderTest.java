package pro.javatar.security.oidc.services;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;

import pro.javatar.security.oidc.model.UserKey;

import org.junit.Before;
import org.junit.Test;

public class OnBehalfOfUsernameHolderTest {

    private OnBehalfOfUsernameHolder holder;

    @Before
    public void setUp() throws Exception {
        holder = new OnBehalfOfUsernameHolder();
    }

    @Test
    public void checkHoldingUserKeyBetweenThreads() throws Exception {
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
    public void putWrongUserKey() throws Exception {
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
    public void removeUserKey() throws Exception {
        assertThat(holder.getUser(), is(nullValue()));
        UserKey userKey1 = new UserKey("user1", "realm1");
        holder.putUser(userKey1);
        assertThat(holder.getUser(), is(userKey1));

        holder.removeUser();
        assertThat(holder.getUser(), is(nullValue()));
    }
}