package org.itrunner.heroes.dao;

import java.util.List;

import org.apache.ibatis.annotations.Param;
import org.itrunner.heroes.dto.UsersCriteria;
import org.itrunner.heroes.dto.UsersDTO;
import org.springframework.stereotype.Repository;

@Repository
public interface UsersDao {
    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table users
     *
     * @mbggenerated Thu Nov 01 23:33:33 CDT 2018
     */
    int countByCriteria(UsersCriteria example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table users
     *
     * @mbggenerated Thu Nov 01 23:33:33 CDT 2018
     */
    int deleteByCriteria(UsersCriteria example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table users
     *
     * @mbggenerated Thu Nov 01 23:33:33 CDT 2018
     */
    int deleteByPrimaryKey(Long id);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table users
     *
     * @mbggenerated Thu Nov 01 23:33:33 CDT 2018
     */
    int insert(UsersDTO record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table users
     *
     * @mbggenerated Thu Nov 01 23:33:33 CDT 2018
     */
    int insertSelective(UsersDTO record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table users
     *
     * @mbggenerated Thu Nov 01 23:33:33 CDT 2018
     */
    List<UsersDTO> selectByCriteria(UsersCriteria example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table users
     *
     * @mbggenerated Thu Nov 01 23:33:33 CDT 2018
     */
    UsersDTO selectByPrimaryKey(Long id);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table users
     *
     * @mbggenerated Thu Nov 01 23:33:33 CDT 2018
     */
    int updateByCriteriaSelective(@Param("record") UsersDTO record, @Param("example") UsersCriteria example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table users
     *
     * @mbggenerated Thu Nov 01 23:33:33 CDT 2018
     */
    int updateByCriteria(@Param("record") UsersDTO record, @Param("example") UsersCriteria example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table users
     *
     * @mbggenerated Thu Nov 01 23:33:33 CDT 2018
     */
    int updateByPrimaryKeySelective(UsersDTO record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table users
     *
     * @mbggenerated Thu Nov 01 23:33:33 CDT 2018
     */
    int updateByPrimaryKey(UsersDTO record);
}