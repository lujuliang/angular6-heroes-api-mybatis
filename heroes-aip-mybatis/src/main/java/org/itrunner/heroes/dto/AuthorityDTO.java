package org.itrunner.heroes.dto;

public class AuthorityDTO {
    /**
     * This field was generated by MyBatis Generator.
     * This field corresponds to the database column authority.id
     *
     * @mbggenerated Thu Nov 01 23:33:33 CDT 2018
     */
    private Long id;

    /**
     * This field was generated by MyBatis Generator.
     * This field corresponds to the database column authority.authority_name
     *
     * @mbggenerated Thu Nov 01 23:33:33 CDT 2018
     */
    private String authorityName;

    /**
     * This method was generated by MyBatis Generator.
     * This method returns the value of the database column authority.id
     *
     * @return the value of authority.id
     *
     * @mbggenerated Thu Nov 01 23:33:33 CDT 2018
     */
    public Long getId() {
        return id;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method sets the value of the database column authority.id
     *
     * @param id the value for authority.id
     *
     * @mbggenerated Thu Nov 01 23:33:33 CDT 2018
     */
    public void setId(Long id) {
        this.id = id;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method returns the value of the database column authority.authority_name
     *
     * @return the value of authority.authority_name
     *
     * @mbggenerated Thu Nov 01 23:33:33 CDT 2018
     */
    public String getAuthorityName() {
        return authorityName != null?authorityName.trim():null;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method sets the value of the database column authority.authority_name
     *
     * @param authorityName the value for authority.authority_name
     *
     * @mbggenerated Thu Nov 01 23:33:33 CDT 2018
     */
    public void setAuthorityName(String authorityName) {
        this.authorityName = authorityName;
    }
}