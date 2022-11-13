package com.example.customoauthkeycloakmongo.infrastructure.database.mongo.documents;

import lombok.Data;
import lombok.experimental.Accessors;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;
import org.springframework.data.mongodb.core.mapping.FieldType;

@Document("fake-auth-token")
@Data
@Accessors(chain = true)
public class FakeAuthTokenMongoEntity {

    @Id
    private String _id;

    @Field(
            name = "token",
            write = Field.Write.NON_NULL,
            targetType = FieldType.STRING
    )
    private String token;

}
