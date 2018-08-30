package pro.javatar.security.jwt.json;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import java.io.IOException;

public class StringOrArraySerializer extends JsonSerializer<Object> {
    @Override
    public void serialize(Object o, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        String[] array = (String[]) o;
        if (array == null) {
            jsonGenerator.writeNull();
        } else if (array.length == 1) {
            jsonGenerator.writeString(array[0]);
        } else {
            jsonGenerator.writeStartArray();
            for (String s : array) {
                jsonGenerator.writeString(s);
            }
            jsonGenerator.writeEndArray();
        }
    }
}
