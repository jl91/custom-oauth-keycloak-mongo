package com.example.customoauthkeycloakmongo.infrastructure.database.mongo.repositories;

import com.example.customoauthkeycloakmongo.infrastructure.database.mongo.documents.FakeAuthTokenMongoEntity;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface FakeAuthTokenMongoRepository extends MongoRepository<FakeAuthTokenMongoEntity, String> {

    Optional<FakeAuthTokenMongoEntity> findOnByToken(String token);
}
