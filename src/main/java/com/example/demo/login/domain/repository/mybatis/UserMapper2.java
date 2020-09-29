package com.example.demo.login.domain.repository.mybatis;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;

import com.example.demo.login.domain.model.User;

@Mapper
public interface UserMapper2 {

	public boolean insert(User user);

	public List<User> selectMany();

	public User selectOne(String userId);

	public boolean updateOne(User user);

	public boolean deleteOne(String userId);
}
